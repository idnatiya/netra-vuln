package config

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/core/db/migrations"
)

// Migrate applies the embedded <version>_<name>.up.sql files that are not yet
// recorded in schema_migrations, in order, each in its own transaction.
// ponytail: up only; add down migrations when a rollback is ever needed.
func Migrate(db *gorm.DB, log *logrus.Logger) error {
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)`).Error; err != nil {
		return err
	}
	var done []string
	if err := db.Raw(`SELECT version FROM schema_migrations`).Scan(&done).Error; err != nil {
		return err
	}
	files, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		return err
	}
	slices.Sort(files)
	last, applied := "", 0
	for _, f := range files {
		version, _, _ := strings.Cut(f, "_")
		last = version
		if slices.Contains(done, version) {
			continue
		}
		sql, err := fs.ReadFile(migrations.FS, f)
		if err != nil {
			return err
		}
		err = db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(string(sql)).Error; err != nil {
				return err
			}
			return tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, version).Error
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", f, err)
		}
		applied++
	}
	if applied > 0 {
		log.WithFields(logrus.Fields{"version": last, "applied": applied}).Info("Migrations applied")
	}
	return nil
}
