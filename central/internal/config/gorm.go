package config

import (
	"fmt"
	"time"

	driver "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DSN parses database.dsn and forces UTC + parseTime so DATETIME(6) round-trips
// exactly, and clientFoundRows so UPDATE reports matched rows ("no change" is
// not "not found"). multiStatements is for migrations only.
func DSN(viper *viper.Viper, multiStatements bool) (string, error) {
	raw := viper.GetString("database.dsn")
	if raw == "" {
		return "", fmt.Errorf("CENTRAL_DSN (database.dsn) is not set")
	}
	cfg, err := driver.ParseDSN(raw)
	if err != nil {
		return "", fmt.Errorf("parse DSN: %w", err)
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = multiStatements
	cfg.ClientFoundRows = true
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	return cfg.FormatDSN(), nil
}

func NewDatabase(viper *viper.Viper, log *logrus.Logger) *gorm.DB {
	dsn, err := DSN(viper, false)
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.New(&logrusWriter{Logger: log}, logger.Config{
			SlowThreshold:             time.Second * 5,
			Colorful:                  false,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true, // never log values (token hashes, notes)
			LogLevel:                  logger.Warn,
		}),
		TranslateError: false,
	})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}
	connection, err := db.DB()
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}
	connection.SetMaxIdleConns(viper.GetInt("database.pool.idle"))
	connection.SetMaxOpenConns(viper.GetInt("database.pool.max"))
	connection.SetConnMaxLifetime(time.Second * time.Duration(viper.GetInt("database.pool.lifetime")))
	return db
}

type logrusWriter struct {
	Logger *logrus.Logger
}

func (l *logrusWriter) Printf(message string, args ...interface{}) {
	l.Logger.Tracef(message, args...)
}
