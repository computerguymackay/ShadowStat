package service

import (
	"fmt"
	"os"
	"os/exec"
	"text/template"
)

const openrcScriptPath = "/etc/init.d/shadowstat"

// OpenRC capability support varies significantly by version/distro, so
// unlike the systemd path (which grants CAP_NET_RAW/CAP_NET_ADMIN via
// AmbientCapabilities to an unprivileged user), the OpenRC path runs as
// root. This is the "where practical" compromise noted in the project
// roadmap — full unprivileged support is systemd-only for now.
var openrcScriptTemplate = template.Must(template.New("openrc").Parse(`#!/sbin/openrc-run
description="ShadowStat network monitoring"

command="{{.ExecStart}}"
command_args="run --data-dir {{.DataDir}}"
command_background=true
pidfile="/run/shadowstat.pid"

depend() {
	need net
	after firewall
}
`))

// InstallOpenRC writes the init script, marks it executable, adds it to the
// default runlevel, and starts it.
func InstallOpenRC(params UnitParams) error {
	f, err := os.OpenFile(openrcScriptPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("open %s: %w", openrcScriptPath, err)
	}
	defer f.Close()
	if err := openrcScriptTemplate.Execute(f, params); err != nil {
		return fmt.Errorf("write init script: %w", err)
	}
	if err := f.Chmod(0o755); err != nil {
		return fmt.Errorf("chmod %s: %w", openrcScriptPath, err)
	}

	if err := runCmd("rc-update", "add", "shadowstat", "default"); err != nil {
		return err
	}
	return runCmd("rc-service", "shadowstat", "start")
}

// UninstallOpenRC stops the service, removes it from the default runlevel,
// and deletes the init script. Leaves the data directory and service user alone.
func UninstallOpenRC() error {
	if _, err := os.Stat(openrcScriptPath); os.IsNotExist(err) {
		return fmt.Errorf("shadowstat is not installed as an OpenRC service (no %s)", openrcScriptPath)
	}
	_ = runCmd("rc-service", "shadowstat", "stop") // best-effort; may already be stopped
	if err := runCmd("rc-update", "del", "shadowstat", "default"); err != nil {
		return err
	}
	return os.Remove(openrcScriptPath)
}

// StatusOpenRC runs `rc-service shadowstat status`, streaming its output.
func StatusOpenRC() error {
	if _, err := os.Stat(openrcScriptPath); os.IsNotExist(err) {
		fmt.Println("shadowstat is not installed as an OpenRC service.")
		fmt.Println("Run 'sudo shadowstat install-service' to install it.")
		return nil
	}
	cmd := exec.Command("rc-service", "shadowstat", "status")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	return nil
}

// IsOpenRCInstalled reports whether the init script currently exists.
func IsOpenRCInstalled() bool {
	_, err := os.Stat(openrcScriptPath)
	return err == nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, string(out))
	}
	return nil
}
