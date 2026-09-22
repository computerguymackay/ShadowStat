package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdUnitTemplateWithDedicatedUser(t *testing.T) {
	var sb strings.Builder
	err := systemdUnitTemplate.Execute(&sb, UnitParams{
		ExecStart: "/usr/local/bin/shadowstat",
		DataDir:   "/var/lib/shadowstat",
		User:      "shadowstat",
		Group:     "shadowstat",
		AsRoot:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := sb.String()

	for _, want := range []string{
		"ExecStart=/usr/local/bin/shadowstat run --data-dir /var/lib/shadowstat",
		"User=shadowstat",
		"Group=shadowstat",
		"AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN",
		"CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN",
		"ReadWritePaths=/var/lib/shadowstat",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unit file missing %q; got:\n%s", want, out)
		}
	}
}

func TestSystemdUnitTemplateAsRootOmitsUserGroup(t *testing.T) {
	var sb strings.Builder
	err := systemdUnitTemplate.Execute(&sb, UnitParams{
		ExecStart: "/usr/local/bin/shadowstat",
		DataDir:   "/var/lib/shadowstat",
		AsRoot:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := sb.String()

	if strings.Contains(out, "User=") || strings.Contains(out, "Group=") {
		t.Errorf("expected no User=/Group= lines when AsRoot=true, got:\n%s", out)
	}
	// Capabilities are still granted even for root — harmless (root already
	// has them) and keeps the template's capability lines unconditional.
	if !strings.Contains(out, "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN") {
		t.Errorf("expected capabilities line even when AsRoot=true, got:\n%s", out)
	}
}

func TestFindDevDataDirViaXDG(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "shadowstat")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "shadowstat.db"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SUDO_USER", "")
	t.Setenv("XDG_DATA_HOME", tmp)
	t.Setenv("HOME", t.TempDir()) // must not fall through to the real machine's actual home dir

	got, found := FindDevDataDir()
	if !found {
		t.Fatal("expected to find the dev data dir via XDG_DATA_HOME")
	}
	if got != dataDir {
		t.Errorf("found %q, want %q", got, dataDir)
	}
}

func TestFindDevDataDirNoneExists(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("SUDO_USER", "")
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "nonexistent"))
	t.Setenv("HOME", t.TempDir()) // must not fall through to the real machine's actual home dir

	if dir, found := FindDevDataDir(); found {
		t.Errorf("expected no dev data dir to be found, got %q", dir)
	}
}

func TestMigrateDataDirMovesContents(t *testing.T) {
	tmp := t.TempDir()
	source := filepath.Join(tmp, "source")
	target := filepath.Join(tmp, "target")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "shadowstat.db"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "cert.pem"), []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := MigrateDataDir(source, target); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Errorf("expected source dir to be gone after migration, stat err = %v", err)
	}
	b, err := os.ReadFile(filepath.Join(target, "shadowstat.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "data" {
		t.Errorf("db content = %q, want %q", b, "data")
	}
	if _, err := os.Stat(filepath.Join(target, "cert.pem")); err != nil {
		t.Errorf("expected cert.pem to survive migration: %v", err)
	}
}

func TestDetectInitSystemString(t *testing.T) {
	cases := map[InitSystem]string{
		InitSystemd: "systemd",
		InitOpenRC:  "OpenRC",
		InitUnknown: "unknown",
	}
	for sys, want := range cases {
		if got := sys.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", sys, got, want)
		}
	}
}
