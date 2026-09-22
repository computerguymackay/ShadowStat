package detect

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"ShadowStat/internal/store"
)

const (
	// PortScanWindow is the short trailing window scanned for a single
	// target's port fan-out; short because a scan is a burst, not a
	// sustained pattern.
	PortScanWindow = 2 * time.Minute
	// portScanPortsPerTargetThreshold: distinct ports contacted on ONE remote
	// IP within the window to flag as scan-like. This intentionally does NOT
	// trigger on contacting many different hosts (that's normal browsing/app
	// traffic — a page pulling from a dozen CDNs isn't a scan) — only on one
	// target being probed across many of its ports, which legitimate traffic
	// essentially never does (an app talking to one server almost always
	// uses one or two fixed remote ports, e.g. 443).
	portScanPortsPerTargetThreshold = 15
	// portScanDetailPortCap bounds how many ports get stored/shown per alert,
	// in case of an extreme scan (thousands of ports) — the count is still
	// accurate, only the displayed list is capped.
	portScanDetailPortCap = 50
	portScanCooldown      = 15 * time.Minute
)

// PortScan flags a host contacting an unusually large number of distinct
// ports on one remote IP within a short window — the actual signature of a
// port scan. The host raising the alert is always the *initiator* (this
// detector only looks at LAN->WAN traffic), so an alert means "this LAN
// device probed <remote_ip>", never "this LAN device was probed by someone else".
func PortScan(db *store.DB, now time.Time) {
	nowUnix := now.Unix()
	since := nowUnix - int64(PortScanWindow.Seconds())

	targets, err := db.HostTargetPortScans(since, nowUnix, portScanPortsPerTargetThreshold)
	if err != nil {
		log.Printf("detect: port_scan: load target port scans: %v", err)
		return
	}

	cooldownSince := nowUnix - int64(portScanCooldown.Seconds())
	hosts := make(map[int64]*store.Host)

	for _, t := range targets {
		host, ok := hosts[t.HostID]
		if !ok {
			h, err := db.HostByID(t.HostID)
			if err != nil {
				log.Printf("detect: port_scan: load host %d: %v", t.HostID, err)
				continue
			}
			host = h
			hosts[t.HostID] = h
		}

		ports := parsePortsCSV(t.PortsCSV)
		shown := ports
		truncated := false
		if len(shown) > portScanDetailPortCap {
			shown = shown[:portScanDetailPortCap]
			truncated = true
		}

		summary := fmt.Sprintf("%s (this device) probed %d distinct ports on %s — outbound scan initiated by this host",
			hostLabel(host), t.PortCount, t.RemoteIP)
		detail := map[string]any{
			"direction":       "outbound", // this host was the initiator, not the target
			"remote_ip":       t.RemoteIP,
			"port_count":      t.PortCount,
			"ports":           shown,
			"ports_truncated": truncated,
			"window_seconds":  int64(PortScanWindow.Seconds()),
		}

		raiseAlert(db, t.HostID, store.AlertKindPortScan, store.SeverityCritical, summary, detail, t.RemoteIP, nowUnix, cooldownSince)
	}
}

// parsePortsCSV parses a GROUP_CONCAT'd "80,443,8080" string into a sorted
// slice of ints, silently skipping anything unparseable.
func parsePortsCSV(csv string) []int {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		if v, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			ports = append(ports, v)
		}
	}
	sort.Ints(ports)
	return ports
}
