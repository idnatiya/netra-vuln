// Package mysqltest gives integration tests a fresh, migrated MySQL database.
// Tests are skipped unless TEST_MYSQL_DSN is set (see `make test-integration`).
package mysqltest

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"testing"

	driver "github.com/go-sql-driver/mysql"

	"netra-vuln/central/internal/adapter/mysql"
	"netra-vuln/migrations"
)

// Open creates database t_<random>, migrates it, and drops it after the test.
func Open(t testing.TB) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set")
	}
	root, err := mysql.Open(dsn, false)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("t_%x", rand.Uint64())
	if _, err := root.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatalf("create test database (is MySQL up?): %v", err)
	}
	t.Cleanup(func() {
		root.Exec("DROP DATABASE " + name)
		root.Close()
	})

	cfg, err := driver.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName = name
	migDB, err := mysql.Open(cfg.FormatDSN(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer migDB.Close()
	if err := mysql.Migrate(context.Background(), migDB, migrations.FS, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	db, err := mysql.Open(cfg.FormatDSN(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// MigrateAgain re-runs migrations on db's database (for idempotency tests).
func MigrateAgain(t testing.TB, db *sql.DB) {
	t.Helper()
	var name string
	if err := db.QueryRow("SELECT DATABASE()").Scan(&name); err != nil {
		t.Fatal(err)
	}
	cfg, _ := driver.ParseDSN(os.Getenv("TEST_MYSQL_DSN"))
	cfg.DBName = name
	migDB, err := mysql.Open(cfg.FormatDSN(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer migDB.Close()
	if err := mysql.Migrate(context.Background(), migDB, migrations.FS, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
}
