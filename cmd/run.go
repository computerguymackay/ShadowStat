package cmd

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"ShadowStat/internal/auth"
	"ShadowStat/internal/capture"
	"ShadowStat/internal/config"
	"ShadowStat/internal/detect"
	"ShadowStat/internal/rollupjob"
	"ShadowStat/internal/store"
	"ShadowStat/internal/web"
)

// exitNoInteractiveSetup is returned when a first run is detected but stdin
// isn't a terminal to run the setup wizard on (e.g. launched non-interactively
// by a service manager before setup has ever completed).
const exitNoInteractiveSetup = 10

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dataDirFlag := fs.String("data-dir", "", "directory for the database, TLS cert/key, and WAL files (default: auto-detected)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dataDir, err := config.ResolveDataDir(*dataDirFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: %v\n", err)
		return 1
	}

	dbPath := config.DBPath(dataDir)
	_, statErr := os.Stat(dbPath)
	firstRun := os.IsNotExist(statErr)

	db, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: open database: %v\n", err)
		return 1
	}
	defer db.Close()

	setupDone, err := config.IsSetupComplete(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: %v\n", err)
		return 1
	}

	if firstRun || !setupDone {
		if !config.IsInteractive() {
			fmt.Fprintf(os.Stderr,
				"shadowstat: no completed setup found at %s and no interactive terminal available.\n"+
					"Run 'shadowstat run' interactively once to complete first-time setup.\n", dbPath)
			return exitNoInteractiveSetup
		}
		if err := config.RunFirstRunWizard(db); err != nil {
			fmt.Fprintf(os.Stderr, "shadowstat: setup failed: %v\n", err)
			return 1
		}
	}

	settings, err := config.Load(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: %v\n", err)
		return 1
	}

	certPath := config.CertPath(dataDir)
	keyPath := config.KeyPath(dataDir)

	_, lan, err := net.ParseCIDR(settings.LANSubnetCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: invalid stored LAN subnet %q: %v\n", settings.LANSubnetCIDR, err)
		return 1
	}

	bpfFilter, err := capture.CompileLANFilter(settings.LANSubnetCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: compile capture filter: %v\n", err)
		return 1
	}

	src, err := capture.NewPcapgoSource(settings.CaptureInterface, bpfFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: open capture interface %q: %v\n"+
			"(promiscuous-mode capture requires CAP_NET_RAW/CAP_NET_ADMIN or root)\n", settings.CaptureInterface, err)
		return 1
	}

	pipeline := capture.NewPipeline(db, src, lan, time.Duration(settings.FlushInterval)*time.Second)
	scheduler := rollupjob.New(db, settings.RetentionDays)
	detection := detect.New(db)
	sessions := auth.NewManager(db)

	server, err := web.NewServer(settings.HTTPListenAddr, certPath, keyPath, db, sessions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: start web server: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("shadowstat: capturing on %s (LAN %s), listening on https://%s\n",
		settings.CaptureInterface, settings.LANSubnetCIDR, settings.HTTPListenAddr)

	var wg sync.WaitGroup
	var serverErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := pipeline.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "shadowstat: capture pipeline stopped: %v\n", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scheduler.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		detection.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Start(ctx, certPath, keyPath); err != nil {
			serverErr = err
		}
	}()

	wg.Wait()

	if serverErr != nil {
		fmt.Fprintf(os.Stderr, "shadowstat: web server error: %v\n", serverErr)
		return 1
	}
	return 0
}
