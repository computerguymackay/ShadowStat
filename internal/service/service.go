// Package service manages ShadowStat's optional installation as a system
// service (systemd, with best-effort OpenRC support), including creating a
// dedicated unprivileged service user and granting it the capture
// capabilities via the unit itself (AmbientCapabilities) rather than file
// capabilities on the binary — which is what makes it survive a rebuild,
// unlike the setcap-on-the-binary approach used for local development.
package service

import (
	"fmt"
	"os"
	"strings"
)

// SystemDataDir is the canonical location a service-managed installation
// uses, matching config.ResolveDataDir's own preference when running as root.
const SystemDataDir = "/var/lib/shadowstat"

// DefaultServiceUser is the dedicated unprivileged account created (if it
// doesn't already exist) to run the service, unless the operator opts into
// running as root instead.
const DefaultServiceUser = "shadowstat"

const UnitName = "shadowstat.service"

// InitSystem identifies which service manager is available on this host.
type InitSystem int

const (
	InitUnknown InitSystem = iota
	InitSystemd
	InitOpenRC
)

// DetectInitSystem determines the running init system using the standard,
// documented detection methods for each (not just "which binary exists" —
// e.g. systemctl can be installed without systemd actually being PID 1 in
// some container/compat setups).
func DetectInitSystem() InitSystem {
	// /run/systemd/system existing is systemd's own documented signal that
	// it is the running init (see systemd's sd_booted(3)).
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return InitSystemd
	}
	// /sbin/openrc (the OpenRC init binary itself) is OpenRC's own marker;
	// deliberately not treating bare /etc/init.d presence as OpenRC, since
	// that directory also exists on systemd hosts via compat symlinks — we
	// don't want to guess our way into managing a bare sysvinit host
	// incorrectly, so it falls through to InitUnknown instead.
	if _, err := os.Stat("/sbin/openrc"); err == nil {
		return InitOpenRC
	}
	return InitUnknown
}

func (s InitSystem) String() string {
	switch s {
	case InitSystemd:
		return "systemd"
	case InitOpenRC:
		return "OpenRC"
	default:
		return "unknown"
	}
}

// RequireRoot returns a clear, actionable error if not running as root —
// install/uninstall both need it (writing unit files, creating system
// users, calling systemctl/rc-update).
func RequireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (try: sudo %s)", strings.Join(os.Args, " "))
	}
	return nil
}
