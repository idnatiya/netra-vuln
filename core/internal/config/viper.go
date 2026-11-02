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
//	CENTRAL_DB           database.path (SQLite file)
//	CENTRAL_BACKUP_DIR / CENTRAL_BACKUP_AT / CENTRAL_BACKUP_KEEP_DAYS  backup.*
//	CENTRAL_ADDR         web.addr
//	CENTRAL_TRUST_PROXY  web.trust_proxy
//	CENTRAL_LOG_LEVEL    log.level (logrus level, 4 = info)
//	CENTRAL_PUBLIC_URL     web.public_url (URL VMs use to reach central; enables /install.sh)
//	CENTRAL_AGENT_VERSION  agent.version (agent release tag /install.sh downloads)
//	CENTRAL_DASHBOARD_DIR  web.dashboard_dir (built SPA to serve; empty = none)
//	CENTRAL_ADMIN_ALLOW_CIDRS web.admin_allow_cidrs (dashboard/admin/MCP clients; empty = all)
//	CENTRAL_TELEGRAM_TOKEN     telegram.token (bot token; empty = Telegram off)
//	CENTRAL_TELEGRAM_DIGEST_AT telegram.digest_at (daily summary, UTC HH:MM; empty = none)
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
	config.SetDefault("database.path", "central.db")
	config.SetDefault("backup.at", "02:30")
	config.SetDefault("backup.keep_days", 14)
	config.SetDefault("eol.url", "https://endoflife.date/api")
	config.SetDefault("telegram.api_url", "https://api.telegram.org")
	config.SetDefault("telegram.digest_at", "08:00")

	for key, env := range map[string]string{
		"database.path":         "CENTRAL_DB",
		"backup.dir":            "CENTRAL_BACKUP_DIR",
		"eol.url":               "CENTRAL_EOL_URL",
		"backup.at":             "CENTRAL_BACKUP_AT",
		"backup.keep_days":      "CENTRAL_BACKUP_KEEP_DAYS",
		"web.addr":              "CENTRAL_ADDR",
		"web.trust_proxy":       "CENTRAL_TRUST_PROXY",
		"log.level":             "CENTRAL_LOG_LEVEL",
		"web.public_url":        "CENTRAL_PUBLIC_URL",
		"agent.version":         "CENTRAL_AGENT_VERSION",
		"web.dashboard_dir":     "CENTRAL_DASHBOARD_DIR",
		"web.admin_allow_cidrs": "CENTRAL_ADMIN_ALLOW_CIDRS",
		"telegram.token":        "CENTRAL_TELEGRAM_TOKEN",
		"telegram.digest_at":    "CENTRAL_TELEGRAM_DIGEST_AT",
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
