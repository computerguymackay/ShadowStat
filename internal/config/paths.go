package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const systemDataDir = "/var/lib/shadowstat"

// ResolveDataDir determines where ShadowStat's database, certs, and WAL files
// live. There is no config file to store this path in — it's derived fresh on
// every start: an explicit override, else the standard FHS service location if
// usable, else a dev-friendly per-user location. The directory is created if
// it doesn't already exist.
func ResolveDataDir(override string) (string, error) {
	if override != "" {
		if err := os.MkdirAll(override, 0o700); err != nil {
			return "", fmt.Errorf("create data dir %s: %w", override, err)
		}
		return override, nil
	}

	if os.Geteuid() == 0 || dirWritable(systemDataDir) {
		if err := os.MkdirAll(systemDataDir, 0o700); err == nil {
			return systemDataDir, nil
		}
	}

	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		base = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(base, "shadowstat")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create data dir %s: %w", dir, err)
	}
	return dir, nil
}

func dirWritable(dir string) bool {
	if _, err := os.Stat(dir); err != nil {
		// Doesn't exist yet: writable if its parent is (best-effort check).
		return os.MkdirAll(dir, 0o700) == nil
	}
	probe := filepath.Join(dir, ".shadowstat-write-test")
	f, err := os.Create(probe)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(probe)
	return true
}

// DBPath, CertPath, and KeyPath return the standard filenames within dataDir.
func DBPath(dataDir string) string   { return filepath.Join(dataDir, "shadowstat.db") }
func CertPath(dataDir string) string { return filepath.Join(dataDir, "cert.pem") }
func KeyPath(dataDir string) string  { return filepath.Join(dataDir, "key.pem") }
