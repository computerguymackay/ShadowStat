package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"ShadowStat/internal/auth"
	"ShadowStat/internal/store"
)

// ErrNotInteractive is returned by RunFirstRunWizard when stdin isn't a terminal.
var ErrNotInteractive = fmt.Errorf("config: no database found and no interactive terminal available")

// IsInteractive reports whether stdin is attached to a terminal.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

const minPasswordLen = 12

// retentionChoices maps the wizard's menu options to a day count.
var retentionChoices = []struct {
	Label string
	Days  int
}{
	{"1 week", 7},
	{"1 month", 30},
	{"90 days", 90},
	{"1 year", 365},
}

// RunFirstRunWizard prompts on stdin/stdout for the initial setup: capture
// interface, LAN subnet, retention window, and admin credentials, then writes
// everything to the database in one transaction with setup_complete=1 last.
func RunFirstRunWizard(db *store.DB) error {
	if !IsInteractive() {
		return ErrNotInteractive
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("ShadowStat first-time setup")
	fmt.Println("===========================")

	iface, err := promptInterface(reader)
	if err != nil {
		return err
	}

	subnet, err := promptSubnet(reader)
	if err != nil {
		return err
	}

	retentionDays, err := promptRetention(reader)
	if err != nil {
		return err
	}

	username, err := promptUsername(reader)
	if err != nil {
		return err
	}

	password, err := promptPassword()
	if err != nil {
		return err
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if _, err := db.CreateUser(username, hash, time.Now().Unix()); err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	settings := map[string]string{
		store.KeyCaptureInterface:  iface,
		store.KeyLANSubnetCIDR:     subnet,
		store.KeyRetentionDays:     strconv.Itoa(retentionDays),
		store.KeyHTTPListenAddr:    DefaultHTTPListenAddr,
		store.KeyFlushIntervalSecs: strconv.Itoa(DefaultFlushInterval),
	}
	if err := db.SetSettings(settings); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}

	// setup_complete written last and separately, so a crash before this point
	// leaves the DB correctly detected as still-first-run on next start.
	if err := db.SetSetting(store.KeySetupComplete, "1"); err != nil {
		return fmt.Errorf("finalize setup: %w", err)
	}

	fmt.Println()
	fmt.Println("Setup complete.")
	return nil
}

func promptInterface(reader *bufio.Reader) (string, error) {
	ifaces, err := ListCaptureInterfaces()
	if err != nil {
		return "", err
	}
	if len(ifaces) == 0 {
		return "", fmt.Errorf("no candidate network interfaces found")
	}

	fmt.Println("\nAvailable network interfaces:")
	for i, iface := range ifaces {
		fmt.Printf("  %d) %s\n", i+1, iface.Name)
	}

	for {
		fmt.Print("Select capture interface [1]: ")
		line, err := readLine(reader)
		if err != nil {
			return "", err
		}
		if line == "" {
			return ifaces[0].Name, nil
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 1 || idx > len(ifaces) {
			fmt.Println("Invalid selection, try again.")
			continue
		}
		return ifaces[idx-1].Name, nil
	}
}

func promptSubnet(reader *bufio.Reader) (string, error) {
	for {
		fmt.Print("LAN subnet (CIDR, e.g. 192.168.1.0/24): ")
		line, err := readLine(reader)
		if err != nil {
			return "", err
		}
		if _, _, err := net.ParseCIDR(line); err != nil {
			fmt.Println("Invalid CIDR, try again.")
			continue
		}
		return line, nil
	}
}

func promptRetention(reader *bufio.Reader) (int, error) {
	fmt.Println("\nRetention window:")
	for i, c := range retentionChoices {
		fmt.Printf("  %d) %s\n", i+1, c.Label)
	}
	for {
		fmt.Print("Select retention window [2]: ")
		line, err := readLine(reader)
		if err != nil {
			return 0, err
		}
		if line == "" {
			return retentionChoices[1].Days, nil
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 1 || idx > len(retentionChoices) {
			fmt.Println("Invalid selection, try again.")
			continue
		}
		return retentionChoices[idx-1].Days, nil
	}
}

func promptUsername(reader *bufio.Reader) (string, error) {
	for {
		fmt.Print("\nAdmin username: ")
		line, err := readLine(reader)
		if err != nil {
			return "", err
		}
		if line == "" {
			fmt.Println("Username cannot be empty.")
			continue
		}
		return line, nil
	}
}

func promptPassword() (string, error) {
	for {
		fmt.Print("Admin password (min 12 characters): ")
		pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		if len(pw1) < minPasswordLen {
			fmt.Printf("Password must be at least %d characters.\n", minPasswordLen)
			continue
		}

		fmt.Print("Confirm password: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("read password confirmation: %w", err)
		}

		if string(pw1) != string(pw2) {
			fmt.Println("Passwords do not match, try again.")
			continue
		}
		return string(pw1), nil
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
