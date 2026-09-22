package detect

import (
	"fmt"
	"log"
	"time"

	"ShadowStat/internal/store"
)

const (
	// PortScanWindow is the short trailing window scanned for distinct-peer
	// fan-out; short because a scan is a burst, not a sustained pattern.
	PortScanWindow = 2 * time.Minute
	// portScanDistinctPeerThreshold: distinct (remote_ip, remote_port) pairs
	// contacted by one host within the window to be flagged as scan-like.
	portScanDistinctPeerThreshold = 30
	portScanCooldown              = 15 * time.Minute
)

// PortScan flags hosts contacting an unusually large number of distinct
// remote (ip, port) pairs in a short window — many-ports-on-one-host or
// few-ports-on-many-hosts both show up as a high distinct-pair count.
func PortScan(db *store.DB, now time.Time) {
	nowUnix := now.Unix()
	since := nowUnix - int64(PortScanWindow.Seconds())

	counts, err := db.HostDistinctPeerCounts(since, nowUnix)
	if err != nil {
		log.Printf("detect: port_scan: load distinct peer counts: %v", err)
		return
	}

	cooldownSince := nowUnix - int64(portScanCooldown.Seconds())

	for _, c := range counts {
		if c.Count < portScanDistinctPeerThreshold {
			continue
		}

		host, err := db.HostByID(c.HostID)
		if err != nil {
			log.Printf("detect: port_scan: load host %d: %v", c.HostID, err)
			continue
		}

		summary := fmt.Sprintf("%s contacted %d distinct destinations in the last %s",
			hostLabel(host), c.Count, PortScanWindow)
		detail := map[string]any{"distinct_peers": c.Count, "window_seconds": int64(PortScanWindow.Seconds())}

		raiseAlert(db, c.HostID, store.AlertKindPortScan, store.SeverityCritical, summary, detail, "burst", nowUnix, cooldownSince)
	}
}
