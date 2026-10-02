package detect

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"ShadowStat/internal/geoip"
	"ShadowStat/internal/store"
)

const (
	// GeoWatchlistScanWindow is how far back each run looks for distinct
	// remote peers to check against the configured watchlist.
	GeoWatchlistScanWindow = 2 * time.Minute
	// geoWatchlistCooldown avoids re-alerting the same host+peer repeatedly
	// while a connection to a watchlisted address remains ongoing.
	geoWatchlistCooldown = 24 * time.Hour
)

// ParseGeoWatchlist splits an admin-configured, comma/whitespace-separated
// country code list (e.g. "CN, RU,KP") into a normalized uppercase set.
// Shared by the detector and the settings handler so both agree on what
// counts as a valid entry.
func ParseGeoWatchlist(raw string) map[string]bool {
	out := make(map[string]bool)
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		cc := strings.ToUpper(strings.TrimSpace(part))
		if len(cc) == 2 {
			out[cc] = true
		}
	}
	return out
}

// GeoWatchlist flags LAN hosts observed exchanging traffic with a remote IP
// whose allocated country appears on the admin's watchlist — e.g. a UK-based
// network with no legitimate reason to see connections to/from certain
// countries. An empty or unset watchlist means there's nothing to check and
// the detector raises nothing: unlike the other detectors there is no sane
// site-independent default list, since what counts as "unexpected" is
// entirely dependent on where the network actually operates.
func GeoWatchlist(db *store.DB, now time.Time) {
	raw, ok, err := db.GetSetting(store.KeyGeoWatchlistCountries)
	if err != nil {
		log.Printf("detect: geo_watchlist: load setting: %v", err)
		return
	}
	if !ok {
		return
	}
	watch := ParseGeoWatchlist(raw)
	if len(watch) == 0 {
		return
	}

	nowUnix := now.Unix()
	since := nowUnix - int64(GeoWatchlistScanWindow.Seconds())
	cooldownSince := nowUnix - int64(geoWatchlistCooldown.Seconds())

	peers, err := db.RecentFlowPeers(since, nowUnix)
	if err != nil {
		log.Printf("detect: geo_watchlist: list recent peers: %v", err)
		return
	}

	hosts := make(map[int64]*store.Host)
	seen := make(map[string]bool) // "hostID:remoteIP" — collapse multiple ports to the same peer within one run

	for _, p := range peers {
		key := fmt.Sprintf("%d:%s", p.HostID, p.RemoteIP)
		if seen[key] {
			continue
		}
		seen[key] = true

		ip := net.ParseIP(p.RemoteIP)
		if ip == nil {
			continue
		}
		cc, ok := geoip.CountryForIP(ip)
		if !ok || !watch[cc] {
			continue
		}

		host, ok := hosts[p.HostID]
		if !ok {
			h, err := db.HostByID(p.HostID)
			if err != nil {
				log.Printf("detect: geo_watchlist: load host %d: %v", p.HostID, err)
				continue
			}
			host = h
			hosts[p.HostID] = h
		}

		direction, directionPhrase := classifyPeerDirection(p.HadOutbound, p.HadInbound)
		summary := fmt.Sprintf("%s %s watchlisted-country (%s) address %s", hostLabel(host), directionPhrase, cc, p.RemoteIP)
		detail := map[string]any{
			"remote_ip": p.RemoteIP,
			"country":   cc,
			"direction": direction,
		}

		raiseAlert(db, p.HostID, store.AlertKindGeoWatchlist, store.SeverityWarning, summary, detail,
			p.RemoteIP, nowUnix, cooldownSince)
	}
}
