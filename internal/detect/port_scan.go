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
	// portScanPortsPerTargetThreshold: distinct ports involving ONE peer
	// within the window to flag as scan-like. This intentionally does NOT
	// trigger on contacting many different hosts (that's normal browsing/app
	// traffic — a page pulling from a dozen CDNs isn't a scan) — only on one
	// peer relationship spanning many ports, which legitimate traffic
	// essentially never does (an app talking to one server almost always
	// uses one or two fixed ports, e.g. 443).
	portScanPortsPerTargetThreshold = 15
	// portScanDetailPortCap bounds how many ports get stored/shown per alert,
	// in case of an extreme scan (thousands of ports) — the count is still
	// accurate, only the displayed list is capped.
	portScanDetailPortCap = 50
	portScanCooldown      = 15 * time.Minute
)

// portScanCheck describes one of the three ways port-scan-shaped traffic can
// show up in flows_recent: this host scanning out to the WAN, this host
// scanning out to another LAN device, or another LAN device scanning this
// host. Each is a genuinely different situation, so each gets its own
// summary wording — the whole point being to never leave "who scanned whom"
// ambiguous.
type portScanCheck struct {
	direction      int
	countLocalPort bool // true when peer diversity is measured via *this host's own* ports
	dedupePrefix   string
	buildSummary   func(hostLabel, remoteIP string, portCount int) string
	detailDir      string // "outbound" or "inbound", stored in the alert detail
}

var portScanChecks = []portScanCheck{
	{
		direction:      store.DirLANToWAN,
		countLocalPort: false,
		dedupePrefix:   "wan_out:",
		detailDir:      "outbound",
		buildSummary: func(h, ip string, n int) string {
			return fmt.Sprintf("%s (this device) probed %d distinct ports on %s — outbound scan initiated by this host", h, n, ip)
		},
	},
	{
		direction:      store.DirLANOut,
		countLocalPort: false,
		dedupePrefix:   "lan_out:",
		detailDir:      "outbound",
		buildSummary: func(h, ip string, n int) string {
			return fmt.Sprintf("%s (this device) probed %d distinct ports on LAN peer %s — outbound scan initiated by this host", h, n, ip)
		},
	},
	{
		direction:      store.DirLANIn,
		countLocalPort: true,
		dedupePrefix:   "lan_in:",
		detailDir:      "inbound",
		buildSummary: func(h, ip string, n int) string {
			return fmt.Sprintf("%s was probed on %d distinct ports by %s — another device on the LAN scanned this host (not the other way around)", h, n, ip)
		},
	},
}

// PortScan flags a host contacting — or being contacted on — an unusually
// large number of distinct ports involving one peer within a short window:
// the actual signature of a port scan, whether this host is the one doing it
// (to a WAN or LAN target) or the one having it done to it (by a LAN peer —
// inbound WAN scans aren't visible this way since they'd normally be
// stopped at the router/NAT before reaching the LAN in the first place).
func PortScan(db *store.DB, now time.Time) {
	nowUnix := now.Unix()
	since := nowUnix - int64(PortScanWindow.Seconds())
	cooldownSince := nowUnix - int64(portScanCooldown.Seconds())
	hosts := make(map[int64]*store.Host)

	for _, check := range portScanChecks {
		targets, err := db.HostTargetPortScans(since, nowUnix, check.direction, check.countLocalPort, portScanPortsPerTargetThreshold)
		if err != nil {
			log.Printf("detect: port_scan: load target port scans (dir=%d): %v", check.direction, err)
			continue
		}

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

			summary := check.buildSummary(hostLabel(host), t.RemoteIP, t.PortCount)
			detail := map[string]any{
				"direction":       check.detailDir,
				"remote_ip":       t.RemoteIP,
				"port_count":      t.PortCount,
				"ports":           shown,
				"ports_truncated": truncated,
				"window_seconds":  int64(PortScanWindow.Seconds()),
			}

			raiseAlert(db, t.HostID, store.AlertKindPortScan, store.SeverityCritical, summary, detail,
				check.dedupePrefix+t.RemoteIP, nowUnix, cooldownSince)
		}
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
