package usecase

import (
	"context"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/model/converter"
	"netra-vuln/core/internal/repository"
)

const SessionTTL = 12 * time.Hour

// AuthUseCase handles dashboard logins, sessions, and the signed-in admin's account.
type AuthUseCase struct {
	DB                     *gorm.DB
	Log                    *logrus.Logger
	Validate               *validator.Validate
	AdminUserRepository    *repository.AdminUserRepository
	AdminSessionRepository *repository.AdminSessionRepository
	BcryptCost             int // 0 = bcrypt.DefaultCost
}

func NewAuthUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, adminUserRepository *repository.AdminUserRepository,
	adminSessionRepository *repository.AdminSessionRepository) *AuthUseCase {
	return &AuthUseCase{DB: db, Log: log, Validate: validate, AdminUserRepository: adminUserRepository,
		AdminSessionRepository: adminSessionRepository}
}

func (c *AuthUseCase) cost() int {
	if c.BcryptCost == 0 {
		return bcrypt.DefaultCost
	}
	return c.BcryptCost
}

var (
	dummyOnce sync.Once
	dummyHash []byte
)

// Login returns a new session token. Every credential failure is 401, and an
// unknown user still pays for one bcrypt comparison so timing does not reveal
// which usernames exist.
func (c *AuthUseCase) Login(ctx context.Context, request *model.LoginUserRequest) (string, *model.Auth, error) {
	if err := c.Validate.Struct(request); err != nil {
		return "", nil, fiber.ErrUnauthorized
	}
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	user := new(entity.AdminUser)
	err := c.AdminUserRepository.FindByUsername(tx, user, request.Username)
	if err != nil && !isNotFound(err) {
		c.Log.Warnf("Failed find admin : %+v", err)
		return "", nil, fiber.ErrInternalServerError
	}
	if err != nil || !user.Active() {
		dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), c.cost()) })
		bcrypt.CompareHashAndPassword(dummyHash, []byte(request.Password))
		return "", nil, fiber.ErrUnauthorized
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)) != nil {
		return "", nil, fiber.ErrUnauthorized
	}

	t := now()
	token, hash := NewToken()
	session := &entity.AdminSession{UserID: user.ID, TokenHash: hash, CreatedAt: t, ExpiresAt: t.Add(SessionTTL),
		IP: truncateBytes(request.IP, 45), UserAgent: truncateBytes(request.UserAgent, 255)}
	if err := c.AdminSessionRepository.DeleteExpired(tx, t); err != nil {
		c.Log.Warnf("Failed delete expired sessions : %+v", err)
		return "", nil, fiber.ErrInternalServerError
	}
	if err := tx.Omit("User").Create(session).Error; err != nil {
		c.Log.Warnf("Failed create session : %+v", err)
		return "", nil, fiber.ErrInternalServerError
	}
	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return "", nil, fiber.ErrInternalServerError
	}
	session.User = *user
	return token, converter.SessionToAuth(session), nil
}

// Verify returns the admin behind a session token.
func (c *AuthUseCase) Verify(ctx context.Context, token string) (*model.Auth, error) {
	if token == "" {
		return nil, fiber.ErrUnauthorized
	}
	session := new(entity.AdminSession)
	if err := c.AdminSessionRepository.FindActiveByTokenHash(c.DB.WithContext(ctx), session, HashToken(token), now()); err != nil {
		if isNotFound(err) {
			return nil, fiber.ErrUnauthorized
		}
		c.Log.Warnf("Failed find session : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.SessionToAuth(session), nil
}

func (c *AuthUseCase) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if err := c.AdminSessionRepository.DeleteByTokenHash(c.DB.WithContext(ctx), HashToken(token)); err != nil {
		c.Log.Warnf("Failed delete session : %+v", err)
		return fiber.ErrInternalServerError
	}
	return nil
}

// ChangePassword sets a new password for the signed-in admin after checking the
// current one, then signs out every other session of that admin. A wrong
// current password is 400, not 401: the session stays valid.
func (c *AuthUseCase) ChangePassword(ctx context.Context, auth *model.Auth, request *model.ChangePasswordRequest) (*model.CountResponse, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	if !validPasswordLength(request.NewPassword) {
		return nil, fiber.NewError(fiber.StatusBadRequest, "the new password must be 12-72 bytes")
	}
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	user := new(entity.AdminUser)
	if err := c.AdminUserRepository.FindById(tx, user, auth.UserID); err != nil {
		c.Log.Warnf("Failed find admin : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.CurrentPassword)) != nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "current password is wrong")
	}
	if request.CurrentPassword == request.NewPassword {
		return nil, fiber.NewError(fiber.StatusBadRequest, "the new password must differ from the current one")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), c.cost())
	if err != nil {
		c.Log.Warnf("Failed hash password : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if err := c.AdminUserRepository.UpdatePassword(tx, user.ID, string(hash)); err != nil {
		c.Log.Warnf("Failed update password : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	n, err := c.AdminSessionRepository.DeleteOthers(tx, user.ID, auth.SessionID)
	if err != nil {
		c.Log.Warnf("Failed delete other sessions : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	c.Log.Infof("Admin password changed : %s, signed out %d other sessions", user.Username, n)
	return &model.CountResponse{Count: int(n)}, nil
}

// Sessions lists the admin's active sessions with the caller's own marked current.
func (c *AuthUseCase) Sessions(ctx context.Context, auth *model.Auth) ([]model.SessionResponse, error) {
	sessions, err := c.AdminSessionRepository.FindActiveByUser(c.DB.WithContext(ctx), auth.UserID, now())
	if err != nil {
		c.Log.Warnf("Failed list sessions : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(sessions, func(s entity.AdminSession) model.SessionResponse {
		return converter.SessionToResponse(s, auth.SessionID)
	}), nil
}

// RevokeSession signs out one of the admin's other sessions; the current one is
// ended with logout instead (409). Another admin's session is 404.
func (c *AuthUseCase) RevokeSession(ctx context.Context, auth *model.Auth, request *model.RevokeSessionRequest) error {
	if err := c.Validate.Struct(request); err != nil {
		return invalid(err)
	}
	if request.ID == auth.SessionID {
		return fiber.NewError(fiber.StatusConflict, "this is the current session; sign out instead")
	}
	n, err := c.AdminSessionRepository.DeleteByUserAndId(c.DB.WithContext(ctx), auth.UserID, request.ID)
	if err != nil {
		c.Log.Warnf("Failed delete session : %+v", err)
		return fiber.ErrInternalServerError
	}
	if n == 0 {
		return fiber.NewError(fiber.StatusNotFound, "session not found")
	}
	return nil
}

// RevokeOtherSessions signs out every session of the admin except the caller's.
func (c *AuthUseCase) RevokeOtherSessions(ctx context.Context, auth *model.Auth) (*model.CountResponse, error) {
	n, err := c.AdminSessionRepository.DeleteOthers(c.DB.WithContext(ctx), auth.UserID, auth.SessionID)
	if err != nil {
		c.Log.Warnf("Failed delete other sessions : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return &model.CountResponse{Count: int(n)}, nil
}
