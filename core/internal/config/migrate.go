package config

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratemysql "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"netra-vuln/core/db/migrations"
)

// Migrate applies the embedded golang-migrate migrations (db/migrations) up to
// the latest version. golang-migrate takes a MySQL advisory lock, so concurrent
// runs do not race.
func Migrate(viper *viper.Viper, log *logrus.Logger) error {
	dsn, err := DSN(viper, true) // migration files hold several statements
	if err != nil {
		return err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return err
	}
	driver, err := migratemysql.WithInstance(db, &migratemysql.Config{})
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "mysql", driver)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	version, dirty, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return err
	}
	log.WithFields(logrus.Fields{"version": version, "dirty": dirty}).Info("Migrations applied")
	return nil
}
