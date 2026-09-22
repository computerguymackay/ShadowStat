package detect

import (
	"fmt"
	"log"
	"time"

	"ShadowStat/internal/store"
)

const (
	// NewDestinationScanWindow is how far back each run looks for freshly
	// observed peers in flows_recent.
	NewDestinationScanWindow = 2 * time.Minute
	// NewDestinationNoveltyWindow: a peer not contacted in this long counts as
	// "new" again even if it was seen before — matches "never seen in the last
	// 30 days" from the spec, not "never seen ever".
	NewDestinationNoveltyWindow = 30 * 24 * time.Hour
	// NewDestinationLearningPeriod suppresses alerts for hosts younger than
	// this, so a host's first days of (entirely novel) traffic don't produce
	// an alert storm.
	NewDestinationLearningPeriod = 3 * 24 * time.Hour
	// newDestinationCooldown avoids re-alerting the same host+peer repeatedly
	// within a run's scan cadence.
	newDestinationCooldown = 6 * time.Hour
)

// NewDestinations flags (host, remote peer) pairs seen in the scan window that
// haven't been contacted by that host in the last 30 days (or ever).
func NewDestinations(db *store.DB, now time.Time) {
	nowUnix := now.Unix()
	since := nowUnix - int64(NewDestinationScanWindow.Seconds())

	peers, err := db.RecentFlowPeers(since, nowUnix)
	if err != nil {
		log.Printf("detect: new_destination: list recent peers: %v", err)
		return
	}

	hosts := make(map[int64]*store.Host)
	noveltyCutoff := nowUnix - int64(NewDestinationNoveltyWindow.Seconds())
	learningCutoff := int64(NewDestinationLearningPeriod.Seconds())
	alertCooldown := nowUnix - int64(newDestinationCooldown.Seconds())

	for _, p := range peers {
		host, ok := hosts[p.HostID]
		if !ok {
			h, err := db.HostByID(p.HostID)
			if err != nil {
				log.Printf("detect: new_destination: load host %d: %v", p.HostID, err)
				continue
			}
			host = h
			hosts[p.HostID] = h
		}

		lastSeen, known, err := db.KnownPeerLastSeen(p.HostID, p.RemoteIP, p.RemotePort)
		if err != nil {
			log.Printf("detect: new_destination: lookup known peer: %v", err)
			continue
		}
		isNew := !known || lastSeen < noveltyCutoff

		if err := db.UpsertKnownPeer(p.HostID, p.RemoteIP, p.RemotePort, nowUnix); err != nil {
			log.Printf("detect: new_destination: upsert known peer: %v", err)
		}

		if !isNew {
			continue
		}
		if nowUnix-host.FirstSeen < learningCutoff {
			continue // host itself is still new; don't alert on its entire baseline
		}

		direction, directionPhrase := classifyPeerDirection(p.HadOutbound, p.HadInbound)

		dedupeKey := fmt.Sprintf("%s:%d", p.RemoteIP, p.RemotePort)
		summary := fmt.Sprintf("%s %s new destination %s:%d", hostLabel(host), directionPhrase, p.RemoteIP, p.RemotePort)
		detail := map[string]any{
			"remote_ip":   p.RemoteIP,
			"remote_port": p.RemotePort,
			"direction":   direction,
		}

		severity := store.SeverityInfo
		if direction == "inbound" {
			// An external host reaching in with no corresponding outbound request
			// from this device is more notable than this device simply browsing
			// somewhere new — could be an unsolicited probe.
			severity = store.SeverityWarning
		}

		raiseAlert(db, p.HostID, store.AlertKindNewDestination, severity, summary, detail, dedupeKey, nowUnix, alertCooldown)
	}
}
