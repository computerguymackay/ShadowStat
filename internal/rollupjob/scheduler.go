// Package rollupjob periodically rolls flows_recent up into the 1m/5m/1h/1d
// rollup tables and prunes old data per the two-tier retention design.
package rollupjob

import (
	"context"
	"log"
	"time"

	"ShadowStat/internal/store"
)

// Per-tier retention caps. Implementation constants, not user-facing settings,
// to keep the settings UI simple: 1m/5m/1h are superseded by coarser tiers well
// before these windows expire, so keeping more of them just wastes space.
const (
	flowsRecentWindow = 24 * time.Hour
	rollup1mRetention = 7 * 24 * time.Hour
	rollup5mRetention = 60 * 24 * time.Hour
	rollup1hRetention = 2 * 365 * 24 * time.Hour
)

// Scheduler drives the rollup and retention job on independent tickers per
// granularity, all funneled through this single goroutine so writer-side
// statements never race each other.
type Scheduler struct {
	db            *store.DB
	retentionDays int
}

// New creates a Scheduler. retentionDays governs how long rollup_1d data is kept.
func New(db *store.DB, retentionDays int) *Scheduler {
	return &Scheduler{db: db, retentionDays: retentionDays}
}

// Run blocks, driving rollups and pruning until ctx is canceled.
func (s *Scheduler) Run(ctx context.Context) {
	tick1m := time.NewTicker(time.Minute)
	tick5m := time.NewTicker(5 * time.Minute)
	tick1h := time.NewTicker(time.Hour)
	tick1d := time.NewTicker(24 * time.Hour)
	tickPrune := time.NewTicker(time.Hour)
	defer tick1m.Stop()
	defer tick5m.Stop()
	defer tick1h.Stop()
	defer tick1d.Stop()
	defer tickPrune.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick1m.C:
			s.rollup1m()
		case <-tick5m.C:
			s.rollupFiner("1m", "5m", 5*time.Minute)
		case <-tick1h.C:
			s.rollupFiner("5m", "1h", time.Hour)
		case <-tick1d.C:
			s.rollupFiner("1h", "1d", 24*time.Hour)
		case <-tickPrune.C:
			s.prune()
		}
	}
}

func (s *Scheduler) rollup1m() {
	to := time.Now().Truncate(time.Minute)
	from := to.Add(-time.Minute)
	if err := s.db.RollupFromFlowsRecent(from.Unix(), to.Unix()); err != nil {
		log.Printf("rollupjob: 1m rollup: %v", err)
	}
}

func (s *Scheduler) rollupFiner(src, dst string, width time.Duration) {
	to := time.Now().Truncate(width)
	from := to.Add(-width)
	if err := s.db.RollupFromFiner(src, dst, int64(width.Seconds()), from.Unix(), to.Unix()); err != nil {
		log.Printf("rollupjob: %s->%s rollup: %v", src, dst, err)
	}
}

func (s *Scheduler) prune() {
	now := time.Now()

	if err := s.db.PruneFlowsRecent(now.Add(-flowsRecentWindow).Unix()); err != nil {
		log.Printf("rollupjob: prune flows_recent: %v", err)
	}
	if err := s.db.PruneRollup("1m", now.Add(-rollup1mRetention).Unix()); err != nil {
		log.Printf("rollupjob: prune rollup_1m: %v", err)
	}
	if err := s.db.PruneRollup("5m", now.Add(-rollup5mRetention).Unix()); err != nil {
		log.Printf("rollupjob: prune rollup_5m: %v", err)
	}
	if err := s.db.PruneRollup("1h", now.Add(-rollup1hRetention).Unix()); err != nil {
		log.Printf("rollupjob: prune rollup_1h: %v", err)
	}
	retention := time.Duration(s.retentionDays) * 24 * time.Hour
	if err := s.db.PruneRollup("1d", now.Add(-retention).Unix()); err != nil {
		log.Printf("rollupjob: prune rollup_1d: %v", err)
	}
	if err := s.db.IncrementalVacuum(); err != nil {
		log.Printf("rollupjob: incremental vacuum: %v", err)
	}
}
