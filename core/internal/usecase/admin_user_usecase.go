package usecase

import (
	"context"
	"fmt"

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

// AdminUserUseCase backs the `central admin` CLI; admins are never created from the dashboard.
type AdminUserUseCase struct {
	DB                  *gorm.DB
	Log                 *logrus.Logger
	Validate            *validator.Validate
	AdminUserRepository *repository.AdminUserRepository
	BcryptCost          int // 0 = bcrypt.DefaultCost
}

func NewAdminUserUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate,
	adminUserRepository *repository.AdminUserRepository) *AdminUserUseCase {
	return &AdminUserUseCase{DB: db, Log: log, Validate: validate, AdminUserRepository: adminUserRepository}
}

func (c *AdminUserUseCase) hash(request *model.CreateAdminRequest) (string, error) {
	if err := c.Validate.Struct(request); err != nil {
		return "", invalid(err)
	}
	if !validPasswordLength(request.Password) {
		return "", fiber.NewError(fiber.StatusBadRequest, "password must be 12-72 bytes")
	}
	cost := c.BcryptCost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	h, err := bcrypt.GenerateFromPassword([]byte(request.Password), cost)
	if err != nil {
		return "", fiber.ErrInternalServerError
	}
	return string(h), nil
}

func (c *AdminUserUseCase) Create(ctx context.Context, request *model.CreateAdminRequest) error {
	hash, err := c.hash(request)
	if err != nil {
		return err
	}
	user := &entity.AdminUser{Username: request.Username, PasswordHash: hash, CreatedAt: now()}
	if err := c.AdminUserRepository.Create(c.DB.WithContext(ctx), user); err != nil {
		if isDuplicate(err) {
			return fiber.NewError(fiber.StatusConflict, fmt.Sprintf("admin %q already exists", request.Username))
		}
		c.Log.Warnf("Failed create admin : %+v", err)
		return fiber.ErrInternalServerError
	}
	return nil
}

// SetPassword replaces an admin's password; existing sessions stay valid.
func (c *AdminUserUseCase) SetPassword(ctx context.Context, request *model.CreateAdminRequest) error {
	hash, err := c.hash(request)
	if err != nil {
		return err
	}
	db := c.DB.WithContext(ctx)
	user := new(entity.AdminUser)
	if err := c.AdminUserRepository.FindByUsername(db, user, request.Username); err != nil {
		if isNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("admin %q not found", request.Username))
		}
		return fiber.ErrInternalServerError
	}
	if err := c.AdminUserRepository.UpdatePassword(db, user.ID, hash); err != nil {
		c.Log.Warnf("Failed update password : %+v", err)
		return fiber.ErrInternalServerError
	}
	return nil
}

func (c *AdminUserUseCase) List(ctx context.Context) ([]model.AdminUserResponse, error) {
	users, err := c.AdminUserRepository.FindAll(c.DB.WithContext(ctx))
	if err != nil {
		c.Log.Warnf("Failed list admins : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(users, converter.AdminUserToResponse), nil
}
