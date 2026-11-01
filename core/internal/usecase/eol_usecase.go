package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/model/converter"
	"netra-vuln/core/internal/repository"
)

// EOLUseCase keeps the endoflife.date cycles and evaluates host software against them.
type EOLUseCase struct {
	DB                 *gorm.DB
	Log                *logrus.Logger
	BaseURL            string // https://endoflife.date/api
	HTTP               *http.Client
	EOLRepository      *repository.EOLRepository
	SoftwareRepository *repository.SoftwareRepository
	HostRepository     *repository.HostRepository
}

func NewEOLUseCase(db *gorm.DB, log *logrus.Logger, baseURL string, eol *repository.EOLRepository,
	software *repository.SoftwareRepository, hosts *repository.HostRepository) *EOLUseCase {
	return &EOLUseCase{DB: db, Log: log, BaseURL: baseURL, HTTP: &http.Client{Timeout: 20 * time.Second},
		EOLRepository: eol, SoftwareRepository: software, HostRepository: hosts}
}

// Refresh downloads every product's cycles. A product that fails keeps its
// previous data; the error reports how many failed.
func (c *EOLUseCase) Refresh(ctx context.Context) error {
	products := entity.AllEOLProducts()
	slices.Sort(products)
	failed, total := 0, 0
	for _, p := range products {
		cycles, err := c.fetch(ctx, p)
		if err == nil {
			err = c.EOLRepository.ReplaceProduct(c.DB.WithContext(ctx), p, cycles)
		}
		if err != nil {
			failed++
			c.Log.WithError(err).WithField("product", p).Warn("EOL fetch failed")
			continue
		}
		total += len(cycles)
	}
	c.Log.WithFields(logrus.Fields{"products": len(products) - failed, "cycles": total, "failed": failed}).Info("EOL data refreshed")
	if failed > 0 {
		return fmt.Errorf("%d of %d products failed", failed, len(products))
	}
	return nil
}

// endoflife.date returns cycle as a string or number, eol as a date or bool.
type eolEntry struct {
	Cycle  any `json:"cycle"`
	EOL    any `json:"eol"`
	Latest any `json:"latest"`
}

func (c *EOLUseCase) fetch(ctx context.Context, product string) ([]entity.EOLCycle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/"+product+".json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", product, res.StatusCode)
	}
	var entries []eolEntry
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&entries); err != nil {
		return nil, fmt.Errorf("%s: %w", product, err)
	}
	t := now()
	out := make([]entity.EOLCycle, 0, len(entries))
	for _, e := range entries {
		if cy := scalar(e.Cycle); cy != "" {
			out = append(out, entity.EOLCycle{Product: product, Cycle: cy, EOL: scalar(e.EOL), Latest: scalar(e.Latest), FetchedAt: t})
		}
	}
	return out, nil
}

func scalar(v any) string {
	switch v := v.(type) {
	case string:
		return truncateBytes(v, 64)
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// RunRefresh refreshes now and then every interval until ctx ends.
func (c *EOLUseCase) RunRefresh(ctx context.Context, interval time.Duration) {
	for {
		_ = c.Refresh(ctx) // failures are logged per product
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// evaluate returns the software (OS first) of each host with its EOL status.
func (c *EOLUseCase) evaluate(db *gorm.DB, hosts []entity.HostSummary) (map[int64][]entity.SoftwareEOL, error) {
	hostID := int64(0)
	if len(hosts) == 1 {
		hostID = hosts[0].ID
	}
	software, err := c.SoftwareRepository.ByHost(db, hostID)
	if err != nil {
		return nil, err
	}
	cycles, err := c.EOLRepository.All(db)
	if err != nil {
		return nil, err
	}
	t := now()
	out := map[int64][]entity.SoftwareEOL{}
	for _, h := range hosts {
		rows := software[h.ID]
		if os, ok := entity.OSSoftware(h.Meta); ok {
			rows = append([]entity.Software{os}, rows...)
		}
		out[h.ID] = entity.EvaluateEOL(rows, cycles, t)
	}
	return out, nil
}

// Annotate fills the EOL labels of host summaries.
func (c *EOLUseCase) Annotate(db *gorm.DB, hosts []entity.HostSummary) error {
	eval, err := c.evaluate(db, hosts)
	if err != nil {
		return err
	}
	for i := range hosts {
		hosts[i].SetEOL(eval[hosts[i].ID])
	}
	return nil
}

// HostSoftware lists one host's software with end-of-life status.
func (c *EOLUseCase) HostSoftware(ctx context.Context, hostID int64) ([]model.SoftwareResponse, error) {
	db := c.DB.WithContext(ctx)
	host := new(entity.Host)
	if err := db.First(host, hostID).Error; err != nil {
		if isNotFound(err) {
			return nil, fiber.ErrNotFound
		}
		return nil, fiber.ErrInternalServerError
	}
	eval, err := c.evaluate(db, []entity.HostSummary{{Host: *host}})
	if err != nil {
		c.Log.Warnf("Failed evaluate software : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(eval[host.ID], converter.SoftwareToResponse), nil
}
