// Package test holds central's black-box tests: requests go through the Fiber
// app (app.Test) into a real MySQL database (TEST_MYSQL_DSN, `make test`).
package test

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"netra-vuln/central/internal/config"
	"netra-vuln/central/internal/delivery/http/route"
)

const testDatabase = "vuln_test"

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
	server := os.Getenv("TEST_MYSQL_DSN")
	if server == "" {
		server = "root:test@tcp(127.0.0.1:3317)/"
	}
	if err := recreateDatabase(server); err != nil {
		fmt.Fprintf(os.Stderr, "test MySQL at %s: %v (start it with `make mysql-up`)\n", server, err)
		os.Exit(1)
	}

	viperCfg = viper.New()
	viperCfg.Set("database.dsn", server+testDatabase)
	viperCfg.Set("database.pool.idle", 5)
	viperCfg.Set("database.pool.max", 20)
	viperCfg.Set("database.pool.lifetime", 300)
	log = logrus.New()
	log.SetOutput(io.Discard)
	if err := config.Migrate(viperCfg, log); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	db = config.NewDatabase(viperCfg, log)
	validate = config.NewValidator(viperCfg)
	app = newApp(testLimits)
	os.Exit(m.Run())
}

// newApp bootstraps a Fiber app on the test database; the last one built sets uc.
func newApp(limits route.Limits) *fiber.App {
	a := config.NewFiber(viperCfg, log)
	uc = config.Bootstrap(&config.BootstrapConfig{DB: db, App: a, Log: log, Validate: validate, Config: viperCfg, Limits: limits})
	uc.Auth.BcryptCost = bcrypt.MinCost
	uc.AdminUser.BcryptCost = bcrypt.MinCost
	return a
}

func recreateDatabase(server string) error {
	conn, err := sql.Open("mysql", server)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, q := range []string{"DROP DATABASE IF EXISTS " + testDatabase, "CREATE DATABASE " + testDatabase} {
		if _, err := conn.Exec(q); err != nil {
			return err
		}
	}
	return nil
}
