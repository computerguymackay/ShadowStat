package detect

import (
	"context"
	"log"
	"time"

	"ShadowStat/internal/store"
)

// dnsQueriesRetention bounds dns_queries table growth; it only needs to cover
// the longest detector window (DNSWindow) plus slack, not long-term history.
const dnsQueriesRetention = 48 * time.Hour

// Scheduler runs each detector on its own ticker, all funneled through this
// single goroutine so writer-side statements never race each other — the same
// pattern as internal/rollupjob.Scheduler.
type Scheduler struct {
	db *store.DB
}

// New creates a detection Scheduler.
func New(db *store.DB) *Scheduler {
	return &Scheduler{db: db}
}

// Run blocks, running detectors until ctx is canceled.
func (s *Scheduler) Run(ctx context.Context) {
	tickNewDest := time.NewTicker(NewDestinationScanWindow)
	tickPortScan := time.NewTicker(PortScanWindow)
	tickDNS := time.NewTicker(DNSWindow)
	tickExfil := time.NewTicker(ExfilWindow / 6) // check several times per window
	tickBeacon := time.NewTicker(15 * time.Minute)
	tickPrune := time.NewTicker(time.Hour)
	defer tickNewDest.Stop()
	defer tickPortScan.Stop()
	defer tickDNS.Stop()
	defer tickExfil.Stop()
	defer tickBeacon.Stop()
	defer tickPrune.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickNewDest.C:
			NewDestinations(s.db, time.Now())
		case <-tickPortScan.C:
			PortScan(s.db, time.Now())
		case <-tickDNS.C:
			DNSAnomaly(s.db, time.Now())
		case <-tickExfil.C:
			ExfilRatio(s.db, time.Now())
		case <-tickBeacon.C:
			Beaconing(s.db, time.Now())
		case <-tickPrune.C:
			if err := s.db.PruneDNSQueries(time.Now().Add(-dnsQueriesRetention).Unix()); err != nil {
				log.Printf("detect: prune dns_queries: %v", err)
			}
		}
	}
}
