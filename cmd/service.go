package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"ShadowStat/internal/config"
	"ShadowStat/internal/service"
	"ShadowStat/internal/store"
)

func installServiceCmd(args []string) int {
	fs := flag.NewFlagSet("install-service", flag.ContinueOnError)
	userFlag := fs.String("user", service.DefaultServiceUser, "system user to run the service as")
	asRoot := fs.Bool("root", false, "run the service as root instead of a dedicated unprivileged user")
	dataDirFlag := fs.String("data-dir", "", "data directory to use (default: /var/lib/shadowstat, migrating an existing dev database if found)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := service.RequireRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: %v\n", err)
		return 1
	}

	initSys := service.DetectInitSystem()
	if initSys == service.InitUnknown {
		fmt.Fprintln(os.Stderr, "shadowstat: no supported service manager detected (systemd or OpenRC required)")
		return 1
	}

	if pid, found := findOtherRunningInstance(); found {
		fmt.Fprintf(os.Stderr,
			"shadowstat: another shadowstat process is already running (pid %d).\n"+
				"Stop it first (it will conflict with the service on the same port/capture interface,\n"+
				"and moving its database out from under it while it's running risks data loss):\n"+
				"  sudo kill %d\n", pid, pid)
		return 1
	}

	dataDir, err := resolveServiceDataDir(*dataDirFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: %v\n", err)
		return 1
	}

	if err := verifySetupComplete(dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: %v\n", err)
		return 1
	}

	exe, err := service.ResolveExecutable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: %v\n", err)
		return 1
	}

	params := service.UnitParams{ExecStart: exe, DataDir: dataDir, AsRoot: *asRoot}

	if *asRoot {
		if err := os.Chown(dataDir, 0, 0); err != nil {
			fmt.Fprintf(os.Stderr, "shadowstat: chown data dir to root: %v\n", err)
			return 1
		}
	} else {
		u, err := service.EnsureSystemUser(*userFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "shadowstat: create service user: %v\n", err)
			return 1
		}
		group, err := user.LookupGroupId(u.Gid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "shadowstat: look up group for %s: %v\n", *userFlag, err)
			return 1
		}
		if err := service.ChownDataDir(dataDir, u); err != nil {
			fmt.Fprintf(os.Stderr, "shadowstat: set data dir ownership: %v\n", err)
			return 1
		}
		params.User = u.Username
		params.Group = group.Name
	}

	switch initSys {
	case service.InitSystemd:
		err = service.InstallSystemd(params)
	case service.InitOpenRC:
		err = service.InstallOpenRC(params)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: install service: %v\n", err)
		return 1
	}

	runningAs := params.User
	if *asRoot {
		runningAs = "root"
	}
	fmt.Printf("shadowstat: installed and started as a %s service (running as %s, data dir %s)\n", initSys, runningAs, dataDir)
	fmt.Println("Check status with: shadowstat status")
	if initSys == service.InitSystemd {
		fmt.Println("View logs with: journalctl -u shadowstat.service -f")
	}
	return 0
}

func uninstallServiceCmd(args []string) int {
	if err := service.RequireRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: %v\n", err)
		return 1
	}

	var err error
	switch {
	case service.IsSystemdInstalled():
		err = service.UninstallSystemd()
	case service.IsOpenRCInstalled():
		err = service.UninstallOpenRC()
	default:
		fmt.Fprintln(os.Stderr, "shadowstat: not currently installed as a service")
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: uninstall service: %v\n", err)
		return 1
	}

	fmt.Println("shadowstat: service stopped and uninstalled.")
	fmt.Println("The database, certificate, and service user were left in place.")
	return 0
}

func statusCmd(args []string) int {
	switch {
	case service.IsSystemdInstalled():
		_ = service.StatusSystemd()
	case service.IsOpenRCInstalled():
		_ = service.StatusOpenRC()
	default:
		fmt.Println("shadowstat is not installed as a service.")
		fmt.Println("Run 'sudo shadowstat install-service' to install it.")
	}
	return 0
}

// findOtherRunningInstance scans /proc for another process running this same
// binary as `shadowstat run` (or with no subcommand, which also defaults to
// run) — installing the service out from under a still-running interactive
// instance would fight it for the capture interface and HTTPS port, and
// migrating its database mid-write risks corruption.
//
// Matches on /proc/PID/comm (the process name, always "shadowstat" for this
// binary) rather than resolving /proc/PID/exe — a process whose binary was
// since replaced on disk (e.g. rebuilt while still running, as happens
// routinely during development) has an exe symlink pointing at a deleted
// inode that filepath.EvalSymlinks can't resolve, which would otherwise miss
// exactly the instance this check most needs to catch.
func findOtherRunningInstance() (pid int, found bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	for _, e := range entries {
		candidatePID, err := strconv.Atoi(e.Name())
		if err != nil || candidatePID == os.Getpid() {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", candidatePID))
		if err != nil || strings.TrimSpace(string(comm)) != "shadowstat" {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", candidatePID))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if len(args) <= 1 || args[1] == "run" || strings.HasPrefix(args[1], "-") {
			return candidatePID, true
		}
	}
	return 0, false
}

// resolveServiceDataDir determines which data directory install-service
// should point the unit at: an explicit override, the canonical system
// location if it already has a database, or — the common first-time case —
// migrating a dev-mode database created by an earlier interactive `shadowstat
// run` into the canonical location.
func resolveServiceDataDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}

	target := service.SystemDataDir
	if _, err := os.Stat(config.DBPath(target)); err == nil {
		return target, nil // already installed once, or pre-seeded manually
	}

	sourceDir, found := service.FindDevDataDir()
	if !found {
		return "", fmt.Errorf(
			"no existing ShadowStat database found (checked %s and your own data dir).\n"+
				"Run 'shadowstat run' interactively once first to complete setup, then re-run install-service", target)
	}

	fmt.Printf("shadowstat: migrating existing database from %s to %s\n", sourceDir, target)
	if err := service.MigrateDataDir(sourceDir, target); err != nil {
		return "", fmt.Errorf("migrate data dir: %w", err)
	}
	return target, nil
}

// verifySetupComplete opens the database at dataDir just long enough to
// confirm first-run setup already finished — installing a service against a
// half-configured database would just hang forever with no TTY to prompt on.
func verifySetupComplete(dataDir string) error {
	db, err := store.Open(config.DBPath(dataDir))
	if err != nil {
		return fmt.Errorf("open database at %s: %w", dataDir, err)
	}
	defer db.Close()

	complete, err := config.IsSetupComplete(db)
	if err != nil {
		return fmt.Errorf("check setup status: %w", err)
	}
	if !complete {
		return fmt.Errorf("database at %s hasn't completed first-run setup — run 'shadowstat run' interactively first", dataDir)
	}
	return nil
}
