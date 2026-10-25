package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"netra-vuln/central/internal/domain"
)

type Enroll struct {
	Store Store
	Now   func() time.Time
}

// Run registers a host under a client and returns its new host token.
// An active host with the same hostname is a conflict; a revoked one is
// reactivated with a new token and keeps its history.
func (e *Enroll) Run(ctx context.Context, req domain.EnrollRequest) (string, error) {
	req.Normalize()
	if req.Hostname == "" {
		return "", fmt.Errorf("%w: hostname is empty", domain.ErrInvalid)
	}
	// Unknown client and bad token look the same to the caller.
	client, err := e.Store.ClientByName(ctx, req.ClientName)
	if errors.Is(err, domain.ErrNotFound) {
		return "", domain.ErrUnauthorized
	}
	if err != nil {
		return "", err
	}
	ok, err := e.Store.EnrollTokenValid(ctx, client.ID, HashToken(req.EnrollToken))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", domain.ErrUnauthorized
	}

	token, hash := NewToken()
	t := now(e.Now)
	err = e.Store.InTx(ctx, func(s Store) error {
		h, err := s.HostForUpdate(ctx, client.ID, req.Hostname)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			return s.InsertHost(ctx, client.ID, req.Hostname, req.Meta, hash, t)
		case err != nil:
			return err
		case h.Active():
			return fmt.Errorf("%w: host %q is already enrolled in client %q (revoke it first)",
				domain.ErrConflict, req.Hostname, client.Name)
		default:
			return s.ReactivateHost(ctx, h.ID, req.Meta, hash)
		}
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
