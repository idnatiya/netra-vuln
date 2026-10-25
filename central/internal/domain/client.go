package domain

import (
	"fmt"
	"regexp"
	"time"
)

type Client struct {
	ID   int64
	Name string
	// ScanConfig holds per-client scan overrides in the wire.ScanConfig JSON
	// format (validated before storing); nil = agent defaults.
	ScanConfig []byte
	CreatedAt  time.Time
}

var clientName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func ValidateClientName(name string) error {
	if !clientName.MatchString(name) {
		return fmt.Errorf("%w: client name %q must match %s", ErrInvalid, name, clientName)
	}
	return nil
}
