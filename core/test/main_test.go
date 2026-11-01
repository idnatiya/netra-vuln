// Package test holds central's black-box tests: requests go through the Fiber
// app (app.Test) into a real SQLite database (a temp file per run).
package test

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"netra-vuln/core/internal/config"
	"netra-vuln/core/internal/delivery/http/route"
)

var (
	app      *fiber.App
	db       *gorm.DB
	uc       *config.UseCases
	log      *logrus.Logger
	validate *validator.Validate
	viperCfg *viper.Viper
)

// testLimits are high enough that the suite never trips them; TestRateLimits
// builds its own app with low limits.
var testLimits = route.Limits{Window: time.Minute, PerHostMax: 10_000, EnrollMax: 10_000, AuthMax: 10_000, LoginMax: 10_000}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "central-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	viperCfg = viper.New()
	viperCfg.Set("database.path", dir+"/test.db")
	log = logrus.New()
	if os.Getenv("TEST_LOG") == "" {
		log.SetOutput(io.Discard)
	}
	db = config.NewDatabase(viperCfg, log)
	if err := config.Migrate(db, log); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	validate = config.NewValidator(viperCfg)
	app = newApp(testLimits)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// newApp bootstraps a Fiber app on the test database; the last one built sets uc.
func newApp(limits route.Limits) *fiber.App {
	a := config.NewFiber(viperCfg, log)
	uc = config.Bootstrap(&config.BootstrapConfig{DB: db, App: a, Log: log, Validate: validate, Config: viperCfg, Limits: limits})
	uc.Auth.BcryptCost = bcrypt.MinCost
	uc.AdminUser.BcryptCost = bcrypt.MinCost
	return a
}
