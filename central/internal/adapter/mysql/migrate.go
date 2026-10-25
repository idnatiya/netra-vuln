package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"time"
)

// Migrate applies the *.sql files in fsys that are not yet in schema_migrations,
// in file-name order. db must allow multiStatements. A MySQL advisory lock keeps
// concurrent `central migrate` runs from racing.
//
// MySQL DDL auto-commits, so a file that fails halfway stays half-applied and
// must be fixed by hand; that is why each failure stops the run immediately.
func Migrate(ctx context.Context, db *sql.DB, fsys fs.FS, log *slog.Logger) error {
	conn, err := db.Conn(ctx) // the lock is per connection
	if err != nil {
		return err
	}
	defer conn.Close()

	var got int
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK('central_migrate', 60)`).Scan(&got); err != nil || got != 1 {
		return fmt.Errorf("acquire migration lock: got=%d err=%v", got, err)
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK('central_migrate')`)

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) NOT NULL PRIMARY KEY, applied_at DATETIME(6) NOT NULL)`); err != nil {
		return err
	}

	files, err := fs.Glob(fsys, "*.sql") // sorted
	if err != nil {
		return err
	}
	for _, name := range files {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("apply %s (may be partially applied): %w", name, err)
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			name, time.Now().UTC()); err != nil {
			return err
		}
		log.Info("applied migration", "version", name)
	}
	return nil
}
