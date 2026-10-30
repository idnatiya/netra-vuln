// Package config builds central's dependencies (Viper, Logrus, GORM,
// validator, Fiber) and wires the application in Bootstrap.
package config

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

// NewViper loads config.json (from ./ or ./core) when present, with defaults,
// and lets the environment override it. The env names predate Viper and are
// kept so the compose file and .env stay the same:
//
//	CENTRAL_DSN          database.dsn
//	CENTRAL_ADDR         web.addr
//	CENTRAL_TRUST_PROXY  web.trust_proxy
//	CENTRAL_LOG_LEVEL    log.level (logrus level, 4 = info)
//	CENTRAL_PUBLIC_URL     web.public_url (URL VMs use to reach central; enables /install.sh)
//	CENTRAL_AGENT_VERSION  agent.version (agent release tag /install.sh downloads)
func NewViper() *viper.Viper {
	config := viper.New()
	config.SetConfigName("config")
	config.SetConfigType("json")
	config.AddConfigPath("./")
	config.AddConfigPath("./core")

	config.SetDefault("app.name", "central")
	config.SetDefault("web.addr", ":8080")
	config.SetDefault("web.trust_proxy", false)
	config.SetDefault("log.level", 4)
	config.SetDefault("database.pool.idle", 10)
	config.SetDefault("database.pool.max", 20)
	config.SetDefault("database.pool.lifetime", 300)

	for key, env := range map[string]string{
		"database.dsn":    "CENTRAL_DSN",
		"web.addr":        "CENTRAL_ADDR",
		"web.trust_proxy": "CENTRAL_TRUST_PROXY",
		"log.level":       "CENTRAL_LOG_LEVEL",
		"web.public_url":  "CENTRAL_PUBLIC_URL",
		"agent.version":   "CENTRAL_AGENT_VERSION",
	} {
		_ = config.BindEnv(key, env)
	}

	// The production image has no config file; it is configured by env only.
	if err := config.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
	}
	return config
}
