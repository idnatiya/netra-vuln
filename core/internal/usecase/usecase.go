// Package usecase holds central's application logic. Use cases return
// *fiber.Error values whose code is the HTTP status (as in khannedy's
// golang-clean-architecture) and log the underlying cause.
package usecase

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

// now returns UTC truncated to microseconds, so values written and compared
// within one ingest are exactly equal (times are stored as text).
func now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// NewToken returns a random 256-bit token (hex) and the hash to store.
func NewToken() (token string, hash []byte) {
	b := make([]byte, 32)
	rand.Read(b) // never returns an error (crypto/rand docs)
	token = hex.EncodeToString(b)
	return token, HashToken(token)
}

func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func isNotFound(err error) bool { return errors.Is(err, gorm.ErrRecordNotFound) }

// isDuplicate reports a UNIQUE / PRIMARY KEY violation (SQLite's stable message).
func isDuplicate(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// invalid turns a validator error into a 400 with a readable message.
func invalid(err error) *fiber.Error {
	var ve validator.ValidationErrors
	if !errors.As(err, &ve) {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	msgs := make([]string, len(ve))
	for i, fe := range ve {
		rule := fe.Tag()
		if fe.Param() != "" {
			rule += "=" + fe.Param()
		}
		msgs[i] = fmt.Sprintf("%s: %s", strings.ToLower(fe.Field()), rule)
	}
	return fiber.NewError(fiber.StatusBadRequest, "invalid request: "+strings.Join(msgs, ", "))
}

// truncateBytes cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// validPasswordLength checks bytes, not runes: 72 bytes is bcrypt's input limit.
func validPasswordLength(p string) bool { return len(p) >= 12 && len(p) <= 72 && utf8.ValidString(p) }
