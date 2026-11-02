package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/repository"
)

// TelegramUseCase pushes alerts to Telegram chats and answers read-only bot
// commands. Central only calls the Bot API (long polling); nothing calls central.
type TelegramUseCase struct {
	DB                 *gorm.DB
	Log                *logrus.Logger
	Token              string // empty = disabled
	APIURL             string // https://api.telegram.org
	PublicURL          string // dashboard links; empty = none
	AgentVersion       string // CENTRAL_AGENT_VERSION, for "agent outdated"
	DigestAt           string // UTC HH:MM; empty = no digest
	HTTP               *http.Client
	TelegramRepository *repository.TelegramRepository
	HostRepository     *repository.HostRepository
	EOL                *EOLUseCase
}

func NewTelegramUseCase(db *gorm.DB, log *logrus.Logger, token, apiURL string, telegram *repository.TelegramRepository,
	hosts *repository.HostRepository, eol *EOLUseCase) *TelegramUseCase {
	return &TelegramUseCase{DB: db, Log: log, Token: token, APIURL: strings.TrimRight(apiURL, "/"),
		HTTP: &http.Client{Timeout: 70 * time.Second}, TelegramRepository: telegram, HostRepository: hosts, EOL: eol}
}

func (c *TelegramUseCase) Enabled() bool { return c.Token != "" }

// --- Bot API ---

type tgResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func (c *TelegramUseCase) call(ctx context.Context, method string, payload, out any) error {
	body, _ := json.Marshal(payload)
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.APIURL+"/bot"+c.Token+"/"+method, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := c.HTTP.Do(req)
		if err != nil {
			// The URL holds the token; never log the request error as is.
			return fmt.Errorf("telegram %s: request failed", method)
		}
		var r tgResponse
		err = json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&r)
		res.Body.Close()
		if err != nil {
			return fmt.Errorf("telegram %s: HTTP %d", method, res.StatusCode)
		}
		if res.StatusCode == http.StatusTooManyRequests && attempt == 0 && r.Parameters.RetryAfter > 0 && r.Parameters.RetryAfter <= 60 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(r.Parameters.RetryAfter) * time.Second):
			}
			continue
		}
		if !r.OK {
			return fmt.Errorf("telegram %s: %s", method, r.Description)
		}
		if out != nil {
			return json.Unmarshal(r.Result, out)
		}
		return nil
	}
}

func (c *TelegramUseCase) send(ctx context.Context, chatID int64, text string) error {
	return c.call(ctx, "sendMessage", map[string]any{
		"chat_id": chatID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true,
	}, nil)
}

// deliver sends text to every chat that may see clientID; failures are logged.
func (c *TelegramUseCase) deliver(ctx context.Context, chats []entity.TelegramChat, clientID int64, text string) {
	for _, chat := range chats {
		if chat.Sees(clientID) {
			if err := c.send(ctx, chat.ChatID, text); err != nil {
				c.Log.WithError(err).WithField("chat_id", chat.ChatID).Warn("Telegram send failed")
			}
		}
	}
}

// --- notifier ---

// summaries lists every host with stale flags and EOL labels.
func (c *TelegramUseCase) summaries(db *gorm.DB) ([]entity.HostSummary, error) {
	hosts, err := c.HostRepository.Summaries(db, "")
	if err != nil {
		return nil, err
	}
	t := now()
	for i := range hosts {
		hosts[i].MarkStale(t)
	}
	return hosts, c.EOL.Annotate(db, hosts)
}

// RunNotifier checks for alerts every minute until ctx ends.
func (c *TelegramUseCase) RunNotifier(ctx context.Context) {
	for {
		if err := c.Tick(ctx); err != nil && ctx.Err() == nil {
			c.Log.WithError(err).Warn("Telegram notifier failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// Tick sends the alerts raised since the last tick and the daily digest. The
// first tick only records the current state, so enabling the bot sends no backlog.
func (c *TelegramUseCase) Tick(ctx context.Context) error {
	db := c.DB.WithContext(ctx)
	repo := c.TelegramRepository
	chats, err := repo.Chats(db)
	if err != nil {
		return err
	}
	hosts, err := c.summaries(db)
	if err != nil {
		return err
	}
	last, err := repo.State(db, "last_scan_id")
	if err != nil {
		return err
	}
	silent := last == ""
	if silent {
		chats = nil
	}
	lastID, _ := strconv.ParseInt(last, 10, 64)
	if silent {
		if lastID, err = repo.MaxScanID(db); err != nil {
			return err
		}
	}

	byID := make(map[int64]entity.HostSummary, len(hosts))
	for _, h := range hosts {
		byID[h.ID] = h
	}
	alerts, err := repo.Alerts(db)
	if err != nil {
		return err
	}
	raised := map[entity.NotifyAlert]bool{}
	for _, a := range alerts {
		raised[a] = true
	}
	raise := func(a entity.NotifyAlert) bool { // true when newly raised
		if raised[a] {
			delete(raised, a) // still active: keep
			return false
		}
		if err := repo.AddAlert(db, a); err != nil {
			c.Log.WithError(err).Warn("Failed store alert")
		}
		return true
	}

	// New scans: new critical/high findings and failed-scan streaks.
	scanned, maxID, err := repo.ScannedHosts(db, lastID)
	if err != nil {
		return err
	}
	for _, id := range scanned {
		h, ok := byID[id]
		if !ok || !h.Active() || h.LastScanStatus != entity.StatusOK || h.FirstScan || silent {
			continue
		}
		groups, err := repo.NewInLastScan(db, id)
		if err != nil {
			return err
		}
		if len(groups) > 0 {
			c.deliver(ctx, chats, h.ClientID, entity.MsgNewFindings(h, groups, c.PublicURL))
		}
	}

	var eolItems []entity.EOLItem
	for _, h := range hosts {
		if !h.Active() {
			continue // its alerts stay in raised and are cleared below
		}
		if h.StaleScan || h.StaleHeartbeat {
			if raise(entity.NotifyAlert{HostID: h.ID, Kind: entity.AlertStale}) {
				c.deliver(ctx, chats, h.ClientID, entity.MsgStale(h, c.PublicURL))
			}
		} else if raised[entity.NotifyAlert{HostID: h.ID, Kind: entity.AlertStale}] {
			c.deliver(ctx, chats, h.ClientID, entity.MsgRecovered(h))
		}
		if h.LastScanStatus == entity.StatusError {
			scans, err := repo.RecentScans(db, h.ID, entity.ErrorStreak)
			if err != nil {
				return err
			}
			if streak(scans) {
				if raise(entity.NotifyAlert{HostID: h.ID, Kind: entity.AlertError}) {
					msg := ""
					if scans[0].ErrorMessage != nil {
						msg = *scans[0].ErrorMessage
					}
					c.deliver(ctx, chats, h.ClientID, entity.MsgScanError(h, msg, c.PublicURL))
				}
			}
		}
		for _, l := range h.EOL {
			if raise(entity.NotifyAlert{HostID: h.ID, Kind: entity.AlertEOL, Label: l}) {
				eolItems = append(eolItems, entity.EOLItem{Host: h, Label: l})
			}
		}
		for _, l := range h.EOLSoon {
			if raise(entity.NotifyAlert{HostID: h.ID, Kind: entity.AlertSoon, Label: l}) {
				eolItems = append(eolItems, entity.EOLItem{Host: h, Label: l, Soon: true})
			}
		}
	}
	for _, chat := range chats {
		var mine []entity.EOLItem
		for _, it := range eolItems {
			if chat.Sees(it.Host.ClientID) {
				mine = append(mine, it)
			}
		}
		if len(mine) > 0 {
			if err := c.send(ctx, chat.ChatID, entity.MsgEOL(mine)); err != nil {
				c.Log.WithError(err).WithField("chat_id", chat.ChatID).Warn("Telegram send failed")
			}
		}
	}
	// Whatever was not raised again has cleared.
	for a := range raised {
		if err := repo.DeleteAlert(db, a); err != nil {
			return err
		}
	}
	if err := repo.SetState(db, "last_scan_id", strconv.FormatInt(max(maxID, lastID), 10)); err != nil {
		return err
	}
	return c.digest(ctx, db, chats, hosts)
}

// streak reports whether the newest ErrorStreak scans all failed.
func streak(scans []entity.Scan) bool {
	if len(scans) < entity.ErrorStreak {
		return false
	}
	for _, s := range scans {
		if s.Status != entity.StatusError {
			return false
		}
	}
	return true
}

// digest sends the daily summary once per day after DigestAt (UTC).
func (c *TelegramUseCase) digest(ctx context.Context, db *gorm.DB, chats []entity.TelegramChat, hosts []entity.HostSummary) error {
	at, err := time.Parse("15:04", c.DigestAt)
	if err != nil || len(chats) == 0 {
		return nil
	}
	t := now()
	if t.Hour()*60+t.Minute() < at.Hour()*60+at.Minute() {
		return nil
	}
	day := t.Format(time.DateOnly)
	if last, err := c.TelegramRepository.State(db, "last_digest"); err != nil || last == day {
		return err
	}
	if err := c.TelegramRepository.SetState(db, "last_digest", day); err != nil {
		return err
	}
	for _, chat := range chats {
		text, err := c.digestFor(db, chat, hosts)
		if err != nil {
			return err
		}
		if err := c.send(ctx, chat.ChatID, text); err != nil {
			c.Log.WithError(err).WithField("chat_id", chat.ChatID).Warn("Telegram send failed")
		}
	}
	return nil
}

func visible(chat entity.TelegramChat, hosts []entity.HostSummary) []entity.HostSummary {
	var out []entity.HostSummary
	for _, h := range hosts {
		if chat.Sees(h.ClientID) {
			out = append(out, h)
		}
	}
	return out
}

func (c *TelegramUseCase) digestFor(db *gorm.DB, chat entity.TelegramChat, hosts []entity.HostSummary) (string, error) {
	resolved, err := c.TelegramRepository.ResolvedSince(db, now().Add(-24*time.Hour))
	if err != nil {
		return "", err
	}
	n := 0
	for clientID, count := range resolved {
		if chat.Sees(clientID) {
			n += count
		}
	}
	return entity.MsgDigest(now(), visible(chat, hosts), n, c.AgentVersion), nil
}

// --- bot commands ---

type tgUpdate struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Text string `json:"text"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"message"`
}

// RunBot answers commands via long polling until ctx ends.
func (c *TelegramUseCase) RunBot(ctx context.Context) {
	var offset int64
	for ctx.Err() == nil {
		var updates []tgUpdate
		err := c.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 50, "allowed_updates": []string{"message"}}, &updates)
		if err != nil {
			if ctx.Err() == nil {
				c.Log.WithError(err).Warn("Telegram getUpdates failed")
				select {
				case <-ctx.Done():
				case <-time.After(10 * time.Second):
				}
			}
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			if u.Message == nil || !strings.HasPrefix(u.Message.Text, "/") {
				continue
			}
			reply, err := c.Handle(ctx, u.Message.Chat.ID, u.Message.Text)
			if err != nil {
				c.Log.WithError(err).Warn("Telegram command failed")
				reply = "Something went wrong, see the central log."
			}
			if err := c.send(ctx, u.Message.Chat.ID, reply); err != nil {
				c.Log.WithError(err).WithField("chat_id", u.Message.Chat.ID).Warn("Telegram send failed")
			}
		}
	}
}

const tgHelp = `Commands:
/status — summary of open findings
/host &lt;hostname&gt; — host details and what to fix
/cve &lt;CVE-ID&gt; — hosts affected by a CVE`

// Handle answers one command from chatID. Unknown chats get only their id.
func (c *TelegramUseCase) Handle(ctx context.Context, chatID int64, text string) (string, error) {
	db := c.DB.WithContext(ctx)
	chat, err := c.TelegramRepository.FindChat(db, chatID)
	if err != nil {
		return "", err
	}
	if chat == nil {
		return fmt.Sprintf("Not authorized. Chat id: <code>%d</code>\nAn admin can allow it with <code>central telegram add-chat %d</code>.", chatID, chatID), nil
	}
	fields := strings.Fields(text)
	cmd, _, _ := strings.Cut(fields[0], "@") // /status@my_bot in groups
	arg := ""
	if len(fields) > 1 {
		arg = fields[1]
	}
	switch {
	case cmd == "/status":
		hosts, err := c.summaries(db)
		if err != nil {
			return "", err
		}
		return c.digestFor(db, *chat, hosts)
	case cmd == "/host" && arg != "":
		hosts, err := c.summaries(db)
		if err != nil {
			return "", err
		}
		var replies []string
		for _, h := range visible(*chat, hosts) {
			if strings.EqualFold(h.Hostname, arg) {
				groups, err := c.TelegramRepository.OpenGroups(db, h.ID)
				if err != nil {
					return "", err
				}
				replies = append(replies, entity.MsgHost(h, groups, c.PublicURL))
			}
		}
		if len(replies) == 0 {
			return "Host not found.", nil
		}
		return strings.Join(replies, "\n\n"), nil
	case cmd == "/cve" && arg != "":
		cve := strings.ToUpper(arg)
		rows, err := c.TelegramRepository.CVEHosts(db, cve)
		if err != nil {
			return "", err
		}
		mine := rows[:0]
		for _, r := range rows {
			if chat.Sees(r.ClientID) {
				mine = append(mine, r)
			}
		}
		return entity.MsgCVE(cve, mine), nil
	}
	return tgHelp, nil
}

// --- admin CLI ---

// AddChat allows a chat; clientName "" = admin chat (every client).
func (c *TelegramUseCase) AddChat(ctx context.Context, chatID int64, clientName string) error {
	db := c.DB.WithContext(ctx)
	chat := &entity.TelegramChat{ChatID: chatID, CreatedAt: now()}
	if clientName != "" {
		client := new(entity.Client)
		if err := db.Where("name = ?", clientName).Take(client).Error; err != nil {
			if isNotFound(err) {
				return fiber.NewError(fiber.StatusNotFound, "client not found")
			}
			return fiber.ErrInternalServerError
		}
		chat.ClientID = &client.ID
	}
	if err := db.Create(chat).Error; err != nil {
		if isDuplicate(err) {
			return fiber.NewError(fiber.StatusConflict, "chat already added")
		}
		return fiber.ErrInternalServerError
	}
	return nil
}

func (c *TelegramUseCase) RemoveChat(ctx context.Context, chatID int64) error {
	res := c.DB.WithContext(ctx).Where("chat_id = ?", chatID).Delete(&entity.TelegramChat{})
	if res.Error != nil {
		return fiber.ErrInternalServerError
	}
	if res.RowsAffected == 0 {
		return fiber.ErrNotFound
	}
	return nil
}

func (c *TelegramUseCase) Chats(ctx context.Context) ([]entity.TelegramChat, error) {
	return c.TelegramRepository.Chats(c.DB.WithContext(ctx))
}

// SendTest sends a test message to every allowed chat.
func (c *TelegramUseCase) SendTest(ctx context.Context) error {
	if !c.Enabled() {
		return fiber.NewError(fiber.StatusBadRequest, "CENTRAL_TELEGRAM_TOKEN is not set")
	}
	chats, err := c.Chats(ctx)
	if err != nil {
		return err
	}
	if len(chats) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "no chats; add one with: central telegram add-chat <chat_id>")
	}
	for _, chat := range chats {
		if err := c.send(ctx, chat.ChatID, "✅ netra-vuln central can reach this chat."); err != nil {
			return err
		}
	}
	return nil
}
