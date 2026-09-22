// Package detect implements ShadowStat's behavioral suspicious-activity
// detectors: new destinations, beaconing, upload/download ratio anomalies,
// DNS volume/entropy, and port scanning. Each detector runs periodically,
// reads from the same flows_recent/dns_queries data the capture pipeline
// writes, and raises Alerts through the store — it never talks to the
// capture pipeline directly.
package detect

import (
	"encoding/json"
	"log"

	"ShadowStat/internal/store"
)

// hostLabel returns a host's display name if set (once the future device-naming
// phase populates it), falling back to its IP.
func hostLabel(h *store.Host) string {
	if h.DisplayName.Valid && h.DisplayName.String != "" {
		return h.DisplayName.String
	}
	return h.IP
}

// classifyPeerDirection turns a peer's observed traffic directions into a
// machine-readable label (for the alert's detail JSON, which the web UI
// renders explicitly) and a human summary phrase, so an alert never leaves
// it ambiguous whether the host initiated contact or was reached into.
func classifyPeerDirection(hadOutbound, hadInbound bool) (label, phrase string) {
	switch {
	case hadOutbound && hadInbound:
		return "bidirectional", "exchanged traffic with a"
	case hadOutbound:
		return "outbound", "contacted a"
	case hadInbound:
		return "inbound", "was contacted by a"
	default:
		return "unknown", "was linked to a"
	}
}

// raiseAlert is a small helper shared by every detector: skip if an alert
// with the same dedupe key already fired within the cooldown window, marshal
// detail to JSON, and insert.
func raiseAlert(db *store.DB, hostID int64, kind, severity, summary string, detail any, dedupeKey string, now, cooldownSince int64) {
	exists, err := db.RecentAlertExists(hostID, kind, dedupeKey, cooldownSince)
	if err != nil {
		log.Printf("detect: check recent alert (%s): %v", kind, err)
		return
	}
	if exists {
		return
	}

	detailJSON := ""
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			log.Printf("detect: marshal alert detail (%s): %v", kind, err)
		} else {
			detailJSON = string(b)
		}
	}

	err = db.InsertAlert(store.AlertRecord{
		HostID:     hostID,
		Kind:       kind,
		Severity:   severity,
		Summary:    summary,
		Detail:     detailJSON,
		DedupeKey:  dedupeKey,
		DetectedAt: now,
	})
	if err != nil {
		log.Printf("detect: insert alert (%s): %v", kind, err)
	}
}
