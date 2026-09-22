package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const systemdUnitPath = "/etc/systemd/system/" + UnitName

var systemdUnitTemplate = template.Must(template.New("unit").Parse(`[Unit]
Description=ShadowStat network monitoring
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.ExecStart}} run --data-dir {{.DataDir}}
Restart=on-failure
RestartSec=5
{{- if not .AsRoot}}
User={{.User}}
Group={{.Group}}
{{- end}}
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={{.DataDir}}

[Install]
WantedBy=multi-user.target
`))

// UnitParams fills the systemd unit template.
type UnitParams struct {
	ExecStart string // absolute path to the shadowstat binary
	DataDir   string
	User      string
	Group     string
	AsRoot    bool // true if the service should run as root (User=/Group= omitted)
}

// InstallSystemd writes the unit file, reloads systemd, and enables+starts
// the service (equivalent to `systemctl enable --now`).
func InstallSystemd(params UnitParams) error {
	f, err := os.OpenFile(systemdUnitPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", systemdUnitPath, err)
	}
	defer f.Close()
	if err := systemdUnitTemplate.Execute(f, params); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	if err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if err := runSystemctl("enable", "--now", UnitName); err != nil {
		return err
	}
	return nil
}

// UninstallSystemd stops+disables the service and removes its unit file.
// Deliberately leaves the data directory and service user alone.
func UninstallSystemd() error {
	if _, err := os.Stat(systemdUnitPath); os.IsNotExist(err) {
		return fmt.Errorf("shadowstat is not installed as a systemd service (no %s)", systemdUnitPath)
	}

	if err := runSystemctl("disable", "--now", UnitName); err != nil {
		return err
	}
	if err := os.Remove(systemdUnitPath); err != nil {
		return fmt.Errorf("remove %s: %w", systemdUnitPath, err)
	}
	return runSystemctl("daemon-reload")
}

// StatusSystemd runs `systemctl status` for the service, streaming its
// output directly (including systemctl's own non-zero exit code for a
// stopped/failed unit, which is expected/normal, not an error to report).
func StatusSystemd() error {
	if _, err := os.Stat(systemdUnitPath); os.IsNotExist(err) {
		fmt.Println("shadowstat is not installed as a systemd service.")
		fmt.Println("Run 'sudo shadowstat install-service' to install it.")
		return nil
	}
	cmd := exec.Command("systemctl", "status", UnitName, "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run() // systemctl exits non-zero for inactive/failed units; that's informational, not our error
	return nil
}

// IsSystemdInstalled reports whether the unit file currently exists.
func IsSystemdInstalled() bool {
	_, err := os.Stat(systemdUnitPath)
	return err == nil
}

func runSystemctl(args ...string) error {
	return runCmd("systemctl", args...)
}

// ResolveExecutable returns the absolute, symlink-resolved path to the
// currently running binary, used as the unit's ExecStart.
func ResolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks for %s: %w", exe, err)
	}
	return resolved, nil
}
