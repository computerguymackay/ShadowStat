package detect

import (
	"fmt"
	"log"
	"math"
	"time"

	"ShadowStat/internal/store"
)

const (
	// BeaconingWindow is how far back to look for repeat contact with the
	// same peer; capped at flows_recent's own 24h retention.
	BeaconingWindow = 24 * time.Hour
	// beaconingMinObservations is the minimum number of distinct contacts
	// with a peer needed before interval regularity is statistically meaningful.
	beaconingMinObservations = 5
	// beaconingMinInterval/MaxInterval bound what counts as "beacon-like" —
	// too fast looks like a normal sustained connection re-flushing, too slow
	// is unlikely to be a C2 check-in cadence worth flagging.
	beaconingMinInterval = 10 * time.Second
	beaconingMaxInterval = 6 * time.Hour
	// beaconingMaxCoeffVariation: how regular the intervals must be (stddev /
	// mean) to be flagged. Lower = stricter regularity required.
	beaconingMaxCoeffVariation = 0.2
	beaconingCooldown          = 6 * time.Hour
)

type peerKey struct {
	hostID     int64
	remoteIP   string
	remotePort int
}

// Beaconing flags (host, remote peer) pairs whose contact intervals over the
// scan window are suspiciously regular — a pattern common to C2 check-ins,
// including over encrypted traffic where payload inspection isn't possible.
func Beaconing(db *store.DB, now time.Time) {
	nowUnix := now.Unix()
	since := nowUnix - int64(BeaconingWindow.Seconds())

	rows, err := db.PeerFlowTimestamps(since, nowUnix)
	if err != nil {
		log.Printf("detect: beaconing: list peer timestamps: %v", err)
		return
	}

	groups := make(map[peerKey][]int64)
	for _, r := range rows {
		k := peerKey{r.HostID, r.RemoteIP, r.RemotePort}
		groups[k] = append(groups[k], r.FirstSeen)
	}

	hosts := make(map[int64]*store.Host)
	cooldownSince := nowUnix - int64(beaconingCooldown.Seconds())

	for k, timestamps := range groups {
		if len(timestamps) < beaconingMinObservations {
			continue
		}

		mean, stddev := intervalStats(timestamps)
		if mean <= 0 {
			continue
		}
		if mean < beaconingMinInterval.Seconds() || mean > beaconingMaxInterval.Seconds() {
			continue
		}
		if stddev/mean > beaconingMaxCoeffVariation {
			continue
		}

		host, ok := hosts[k.hostID]
		if !ok {
			h, err := db.HostByID(k.hostID)
			if err != nil {
				log.Printf("detect: beaconing: load host %d: %v", k.hostID, err)
				continue
			}
			host = h
			hosts[k.hostID] = h
		}

		dedupeKey := fmt.Sprintf("%s:%d", k.remoteIP, k.remotePort)
		summary := fmt.Sprintf("%s is contacting %s:%d at suspiciously regular ~%s intervals",
			hostLabel(host), k.remoteIP, k.remotePort, time.Duration(mean*float64(time.Second)).Round(time.Second))
		detail := map[string]any{
			"remote_ip":       k.remoteIP,
			"remote_port":     k.remotePort,
			"mean_interval_s": mean,
			"observations":    len(timestamps),
		}

		raiseAlert(db, k.hostID, store.AlertKindBeaconing, store.SeverityWarning, summary, detail, dedupeKey, nowUnix, cooldownSince)
	}
}

// intervalStats returns the mean and (population) standard deviation of the
// gaps between consecutive, already-sorted timestamps.
func intervalStats(sortedTimestamps []int64) (mean, stddev float64) {
	if len(sortedTimestamps) < 2 {
		return 0, 0
	}
	deltas := make([]float64, 0, len(sortedTimestamps)-1)
	var sum float64
	for i := 1; i < len(sortedTimestamps); i++ {
		d := float64(sortedTimestamps[i] - sortedTimestamps[i-1])
		deltas = append(deltas, d)
		sum += d
	}
	mean = sum / float64(len(deltas))

	var variance float64
	for _, d := range deltas {
		variance += (d - mean) * (d - mean)
	}
	variance /= float64(len(deltas))
	stddev = math.Sqrt(variance)
	return mean, stddev
}
