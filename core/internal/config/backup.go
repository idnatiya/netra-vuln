package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

// Backup writes a consistent copy of the database to file (VACUUM INTO works
// while the server keeps writing). The file must not exist yet.
func Backup(db *gorm.DB, file string) error {
	if err := db.Exec("VACUUM INTO ?", file).Error; err != nil {
		return fmt.Errorf("backup %s: %w", file, err)
	}
	return nil
}

// RunBackups takes a daily backup into backup.dir at backup.at (UTC) until ctx
// ends, keeping backup.keep_days days. Off when backup.dir is empty.
func RunBackups(ctx context.Context, db *gorm.DB, viper *viper.Viper, log *logrus.Logger) {
	dir := viper.GetString("backup.dir")
	if dir == "" {
		return
	}
	at, err := time.Parse("15:04", viper.GetString("backup.at"))
	if err != nil {
		log.Fatalf("CENTRAL_BACKUP_AT: %v", err)
	}
	keep := time.Duration(viper.GetInt("backup.keep_days")) * 24 * time.Hour
	if err := os.MkdirAll(dir, 0o750); err != nil {
		log.Fatalf("CENTRAL_BACKUP_DIR: %v", err)
	}
	for {
		now := time.Now().UTC()
		next := time.Date(now.Year(), now.Month(), now.Day(), at.Hour(), at.Minute(), 0, 0, time.UTC)
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		file := filepath.Join(dir, "central-"+next.Format("20060102-1504")+".db")
		if err := Backup(db, file); err != nil {
			log.WithError(err).Error("Backup failed")
			continue
		}
		log.WithField("file", file).Info("Backup written")
		pruneBackups(dir, keep, log)
	}
}

func pruneBackups(dir string, keep time.Duration, log *logrus.Logger) {
	old, _ := filepath.Glob(filepath.Join(dir, "central-*.db"))
	for _, f := range old {
		if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) > keep {
			if err := os.Remove(f); err != nil {
				log.WithError(err).Warn("Remove old backup")
			}
		}
	}
}
