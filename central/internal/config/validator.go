package config

import (
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"

	"netra-vuln/central/internal/entity"
)

// NewValidator adds the "clientname" and "username" tags (entity patterns).
func NewValidator(viper *viper.Viper) *validator.Validate {
	validate := validator.New()
	_ = validate.RegisterValidation("clientname", func(fl validator.FieldLevel) bool {
		return entity.ClientNamePattern.MatchString(fl.Field().String())
	})
	_ = validate.RegisterValidation("username", func(fl validator.FieldLevel) bool {
		return entity.UsernamePattern.MatchString(fl.Field().String())
	})
	return validate
}
