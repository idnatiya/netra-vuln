package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DSN builds the SQLite DSN for database.path: WAL (readers never block the
// writer), foreign keys on, a busy timeout, BEGIN IMMEDIATE so a transaction
// takes the write lock up front (it replaces SELECT ... FOR UPDATE), and times
// stored as "2006-01-02 15:04:05.999999999-07:00" so SQL date() and string
// comparisons work. The application writes every time in UTC.
func DSN(viper *viper.Viper) (string, error) {
	path := viper.GetString("database.path")
	if path == "" {
		return "", fmt.Errorf("CENTRAL_DB (database.path) is not set")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", fmt.Errorf("create database dir: %w", err)
		}
	}
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "foreign_keys(1)", "busy_timeout(10000)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")
	q.Set("_time_format", "sqlite")
	return "file:" + path + "?" + q.Encode(), nil
}

func NewDatabase(viper *viper.Viper, log *logrus.Logger) *gorm.DB {
	dsn, err := DSN(viper)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.New(&logrusWriter{Logger: log}, logger.Config{
			SlowThreshold:             time.Second * 5,
			Colorful:                  false,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true, // never log values (token hashes, notes)
			LogLevel:                  logger.Warn,
		}),
		TranslateError: false,
		NowFunc:        func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	connection, err := db.DB()
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	// ponytail: one connection serializes all access, so there is never a
	// SQLITE_BUSY between our own goroutines; ample for a few dozen VMs.
	// Raise it (readers in WAL run in parallel) if dashboards ever feel slow.
	connection.SetMaxOpenConns(1)
	return db
}

type logrusWriter struct {
	Logger *logrus.Logger
}

func (l *logrusWriter) Printf(message string, args ...interface{}) {
	l.Logger.Tracef(message, args...)
}
