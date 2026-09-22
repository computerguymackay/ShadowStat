package service

import (
	"fmt"
	"os/exec"
	"os/user"
)

// EnsureSystemUser creates username as a system account (no login shell, no
// home directory of its own) if it doesn't already exist, and returns its
// resolved uid/gid. Shells out to useradd rather than writing /etc/passwd
// directly — the standard, safe way to do this on any Linux distro.
func EnsureSystemUser(username string) (*user.User, error) {
	if u, err := user.Lookup(username); err == nil {
		return u, nil
	}

	cmd := exec.Command("useradd",
		"--system",
		"--no-create-home",
		"--shell", "/usr/sbin/nologin",
		"--comment", "ShadowStat network monitoring service",
		username,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("useradd %s: %w (%s)", username, err, string(out))
	}

	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("useradd reported success but user %s still not found: %w", username, err)
	}
	return u, nil
}
