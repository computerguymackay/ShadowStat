package detect

import (
	"fmt"
	"log"
	"time"

	"ShadowStat/internal/store"
)

const (
	// ExfilWindow is the trailing window over which sent/received bytes are compared.
	ExfilWindow = 1 * time.Hour
	// exfilMinBytesSent floors out hosts with too little upload traffic for the
	// ratio to be meaningful (a single 10KB request with no response is a 100%
	// ratio but not interesting).
	exfilMinBytesSent = 20 * 1024 * 1024 // 20MB
	// exfilRatioThreshold: sent/received must exceed this to be flagged.
	exfilRatioThreshold = 5.0
	exfilCooldown       = 6 * time.Hour
)

// ExfilRatio flags hosts whose outbound (LAN->WAN) traffic in the scan window
// is far larger than their inbound traffic — a pattern consistent with data
// exfiltration (as opposed to normal browsing/streaming, which is recv-heavy).
func ExfilRatio(db *store.DB, now time.Time) {
	nowUnix := now.Unix()
	since := nowUnix - int64(ExfilWindow.Seconds())

	totals, err := db.HostOutboundTotals(since, nowUnix)
	if err != nil {
		log.Printf("detect: exfil_ratio: load host totals: %v", err)
		return
	}

	cooldownSince := nowUnix - int64(exfilCooldown.Seconds())

	for _, t := range totals {
		if t.BytesSent < exfilMinBytesSent {
			continue
		}
		// Treat "no bytes received at all" as an effectively infinite ratio
		// rather than dividing by zero.
		ratio := exfilRatioThreshold + 1
		if t.BytesRecv > 0 {
			ratio = float64(t.BytesSent) / float64(t.BytesRecv)
		}
		if ratio < exfilRatioThreshold {
			continue
		}

		host, err := db.HostByID(t.HostID)
		if err != nil {
			log.Printf("detect: exfil_ratio: load host %d: %v", t.HostID, err)
			continue
		}

		summary := fmt.Sprintf("%s sent %s but only received %s over the last hour (ratio %.1fx)",
			hostLabel(host), fmtBytesShort(t.BytesSent), fmtBytesShort(t.BytesRecv), ratio)
		detail := map[string]any{"bytes_sent": t.BytesSent, "bytes_recv": t.BytesRecv, "ratio": ratio}

		raiseAlert(db, t.HostID, store.AlertKindExfilRatio, store.SeverityWarning, summary, detail, "outbound_ratio", nowUnix, cooldownSince)
	}
}

func fmtBytesShort(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
