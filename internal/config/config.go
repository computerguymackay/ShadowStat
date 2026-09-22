// Package config manages ShadowStat's runtime settings, all of which live in the
// SQLite database — there are no config files or environment variables.
package config

import (
	"fmt"
	"strconv"

	"ShadowStat/internal/store"
)

// Settings is ShadowStat's full runtime configuration, loaded from the settings table.
type Settings struct {
	CaptureInterface string
	LANSubnetCIDR    string
	RetentionDays    int
	TLSCertPath      string
	TLSKeyPath       string
	HTTPListenAddr   string
	FlushInterval    int // seconds
}

// Defaults for values not tied to first-run choices.
const (
	DefaultHTTPListenAddr = ":8443"
	DefaultFlushInterval  = 10
)

// Load reads settings from the database into a Settings struct.
func Load(db *store.DB) (*Settings, error) {
	kv, err := db.AllSettings()
	if err != nil {
		return nil, fmt.Errorf("load settings: %w", err)
	}

	s := &Settings{
		CaptureInterface: kv[store.KeyCaptureInterface],
		LANSubnetCIDR:    kv[store.KeyLANSubnetCIDR],
		TLSCertPath:      kv[store.KeyTLSCertPath],
		TLSKeyPath:       kv[store.KeyTLSKeyPath],
		HTTPListenAddr:   valueOr(kv[store.KeyHTTPListenAddr], DefaultHTTPListenAddr),
	}

	s.RetentionDays, err = strconv.Atoi(valueOr(kv[store.KeyRetentionDays], "30"))
	if err != nil {
		return nil, fmt.Errorf("parse retention_days: %w", err)
	}
	s.FlushInterval, err = strconv.Atoi(valueOr(kv[store.KeyFlushIntervalSecs], strconv.Itoa(DefaultFlushInterval)))
	if err != nil {
		return nil, fmt.Errorf("parse flush_interval_seconds: %w", err)
	}
	return s, nil
}

// IsSetupComplete reports whether the first-run wizard has finished successfully.
func IsSetupComplete(db *store.DB) (bool, error) {
	v, ok, err := db.GetSetting(store.KeySetupComplete)
	if err != nil {
		return false, err
	}
	return ok && v == "1", nil
}

func valueOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
