package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
)

// FindDevDataDir looks for a database created by an interactive (non-root)
// `shadowstat run` — the common path when someone tries the tool out under
// their own account before deciding to install it as a service. Checks
// $SUDO_USER's XDG data dir first (install-service is almost always run via
// sudo by the same person who set it up), then $XDG_DATA_HOME/HOME for the
// current process as a fallback.
func FindDevDataDir() (string, bool) {
	candidates := []string{}

	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			candidates = append(candidates, filepath.Join(u.HomeDir, ".local", "share", "shadowstat"))
		}
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "shadowstat"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".local", "share", "shadowstat"))
	}

	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "shadowstat.db")); err == nil {
			return dir, true
		}
	}
	return "", false
}

// MigrateDataDir moves an existing dev-mode data directory to the canonical
// system location, preserving its contents. Falls back to copy-then-remove
// if the two paths are on different filesystems (os.Rename can't cross
// filesystem boundaries).
func MigrateDataDir(sourceDir, targetDir string) error {
	if err := os.Rename(sourceDir, targetDir); err == nil {
		return nil
	}
	// Rename failed (likely EXDEV, different filesystem) — copy then remove.
	cmd := exec.Command("cp", "-a", sourceDir+"/.", targetDir)
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("create target dir: %w", err)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copy %s to %s: %w (%s)", sourceDir, targetDir, err, string(out))
	}
	if err := os.RemoveAll(sourceDir); err != nil {
		return fmt.Errorf("remove old data dir %s after copy: %w", sourceDir, err)
	}
	return nil
}

// ChownDataDir recursively sets dir's ownership to the given user, so the
// service (running as that user) can read/write its own database, cert, and
// key files.
func ChownDataDir(dir string, u *user.User) error {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parse gid %q: %w", u.Gid, err)
	}

	return filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}
