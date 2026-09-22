package detect

import (
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"ShadowStat/internal/store"
)

const (
	// DNSWindow is the trailing window scanned for both DNS sub-detectors.
	DNSWindow = 10 * time.Minute
	// dnsVolumeThreshold: queries from one host within the window to flag as
	// an abnormal query rate.
	dnsVolumeThreshold = 300
	// dnsEntropyMinLabelLen: shorter leftmost labels are skipped — entropy on
	// a handful of characters is too noisy to be a meaningful DGA signal.
	dnsEntropyMinLabelLen = 12
	// dnsEntropyThreshold: Shannon entropy (bits/char) of the leftmost DNS
	// label above which a domain looks algorithmically generated rather than
	// human-chosen. Heuristic, MVP-grade — expect some false positives on
	// legitimately random-looking CDN/tracking subdomains.
	dnsEntropyThreshold = 3.6
	dnsVolumeCooldown   = 1 * time.Hour
	dnsEntropyCooldown  = 6 * time.Hour
)

// DNSAnomaly flags hosts with an abnormal DNS query rate, and individual
// queried domain names whose leftmost label looks algorithmically generated
// (high character entropy), a common DGA (domain generation algorithm) tell.
func DNSAnomaly(db *store.DB, now time.Time) {
	nowUnix := now.Unix()
	since := nowUnix - int64(DNSWindow.Seconds())

	dnsVolume(db, since, nowUnix)
	dnsEntropy(db, since, nowUnix)
}

func dnsVolume(db *store.DB, since, nowUnix int64) {
	counts, err := db.DNSQueryCounts(since, nowUnix)
	if err != nil {
		log.Printf("detect: dns_anomaly: load query counts: %v", err)
		return
	}
	cooldownSince := nowUnix - int64(dnsVolumeCooldown.Seconds())

	for _, c := range counts {
		if c.Count < dnsVolumeThreshold {
			continue
		}
		host, err := db.HostByID(c.HostID)
		if err != nil {
			log.Printf("detect: dns_anomaly: load host %d: %v", c.HostID, err)
			continue
		}
		summary := fmt.Sprintf("%s made %d DNS queries in the last %s", hostLabel(host), c.Count, DNSWindow)
		detail := map[string]any{"query_count": c.Count, "window_seconds": int64(DNSWindow.Seconds())}
		raiseAlert(db, c.HostID, store.AlertKindDNSAnomaly, store.SeverityWarning, summary, detail, "volume", nowUnix, cooldownSince)
	}
}

func dnsEntropy(db *store.DB, since, nowUnix int64) {
	rows, err := db.DNSQueriesInRange(since, nowUnix)
	if err != nil {
		log.Printf("detect: dns_anomaly: load queries: %v", err)
		return
	}
	cooldownSince := nowUnix - int64(dnsEntropyCooldown.Seconds())

	hosts := make(map[int64]*store.Host)
	for _, r := range rows {
		label := leftmostLabel(r.QName)
		if len(label) < dnsEntropyMinLabelLen {
			continue
		}
		if shannonEntropy(label) < dnsEntropyThreshold {
			continue
		}

		host, ok := hosts[r.HostID]
		if !ok {
			h, err := db.HostByID(r.HostID)
			if err != nil {
				log.Printf("detect: dns_anomaly: load host %d: %v", r.HostID, err)
				continue
			}
			host = h
			hosts[r.HostID] = h
		}

		summary := fmt.Sprintf("%s queried a high-entropy domain name: %s", hostLabel(host), r.QName)
		detail := map[string]any{"qname": r.QName}
		raiseAlert(db, r.HostID, store.AlertKindDNSAnomaly, store.SeverityInfo, summary, detail, "entropy:"+r.QName, nowUnix, cooldownSince)
	}
}

func leftmostLabel(qname string) string {
	qname = strings.TrimSuffix(qname, ".")
	if i := strings.IndexByte(qname, '.'); i >= 0 {
		return qname[:i]
	}
	return qname
}

// shannonEntropy returns the Shannon entropy, in bits per character, of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
