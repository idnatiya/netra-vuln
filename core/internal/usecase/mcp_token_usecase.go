package usecase

import (
	"context"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/model/converter"
	"netra-vuln/core/internal/repository"
)

// mcpTouchEvery limits last_used_at writes to one per token per interval.
const mcpTouchEvery = time.Minute

// McpTokenUseCase manages the Bearer tokens AI clients use for /mcp.
type McpTokenUseCase struct {
	DB                 *gorm.DB
	Log                *logrus.Logger
	Validate           *validator.Validate
	McpTokenRepository *repository.McpTokenRepository
}

func NewMcpTokenUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate,
	mcpTokenRepository *repository.McpTokenRepository) *McpTokenUseCase {
	return &McpTokenUseCase{DB: db, Log: log, Validate: validate, McpTokenRepository: mcpTokenRepository}
}

func (c *McpTokenUseCase) Create(ctx context.Context, auth *model.Auth, request *model.CreateMcpTokenRequest) (*model.CreateMcpTokenResponse, error) {
	request.Name = strings.TrimSpace(request.Name)
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	token, hash := NewToken()
	t := &entity.McpToken{UserID: auth.UserID, Name: request.Name, TokenHash: hash, CanTriage: request.CanTriage, CreatedAt: now()}
	if err := c.DB.WithContext(ctx).Omit("User").Create(t).Error; err != nil {
		c.Log.Warnf("Failed create mcp token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return &model.CreateMcpTokenResponse{McpTokenResponse: converter.McpTokenToResponse(*t), Token: token}, nil
}

func (c *McpTokenUseCase) List(ctx context.Context, auth *model.Auth) ([]model.McpTokenResponse, error) {
	tokens, err := c.McpTokenRepository.FindActiveByUser(c.DB.WithContext(ctx), auth.UserID)
	if err != nil {
		c.Log.Warnf("Failed list mcp tokens : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(tokens, converter.McpTokenToResponse), nil
}

// Revoke revokes one of the admin's tokens; another admin's or an unknown token is 404.
func (c *McpTokenUseCase) Revoke(ctx context.Context, auth *model.Auth, request *model.RevokeMcpTokenRequest) error {
	if err := c.Validate.Struct(request); err != nil {
		return invalid(err)
	}
	n, err := c.McpTokenRepository.Revoke(c.DB.WithContext(ctx), auth.UserID, request.ID, now())
	if err != nil {
		c.Log.Warnf("Failed revoke mcp token : %+v", err)
		return fiber.ErrInternalServerError
	}
	if n == 0 {
		return fiber.NewError(fiber.StatusNotFound, "token not found")
	}
	return nil
}

// Verify returns the admin behind an MCP token and records its use.
func (c *McpTokenUseCase) Verify(ctx context.Context, token string) (*model.Auth, error) {
	if token == "" {
		return nil, fiber.ErrUnauthorized
	}
	db := c.DB.WithContext(ctx)
	t := new(entity.McpToken)
	if err := c.McpTokenRepository.FindActiveByTokenHash(db, t, HashToken(token)); err != nil {
		if isNotFound(err) {
			return nil, fiber.ErrUnauthorized
		}
		c.Log.Warnf("Failed find mcp token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if at := now(); t.LastUsedAt == nil || at.Sub(*t.LastUsedAt) >= mcpTouchEvery {
		if err := c.McpTokenRepository.TouchLastUsed(db, t.ID, at); err != nil {
			c.Log.Warnf("Failed touch mcp token : %+v", err)
		}
	}
	return &model.Auth{UserID: t.UserID, Username: t.User.Username, McpTokenName: t.Name, CanTriage: t.CanTriage}, nil
}
