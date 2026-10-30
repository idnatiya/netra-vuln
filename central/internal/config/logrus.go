package config

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// NewLogger logs JSON to stderr (journald / docker logs). Tokens are never logged.
func NewLogger(viper *viper.Viper) *logrus.Logger {
	log := logrus.New()
	log.SetOutput(os.Stderr)
	log.SetLevel(logrus.Level(viper.GetInt32("log.level")))
	log.SetFormatter(&logrus.JSONFormatter{})
	return log
}
