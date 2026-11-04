// Package rollupjob periodically folds new flows_recent rows into the rollup
// tiers, per-host totals and the daily per-peer breakdown, and prunes old
// data per the two-tier retention design.
package rollupjob

import (
	"context"
	"log"
	"time"

	"ShadowStat/internal/store"
)

// Scheduler runs the rollup and pruning on a single goroutine so writer-side
// statements never race each other.
type Scheduler struct {
	db            *store.DB
	retentionDays int
}

// New creates a Scheduler. retentionDays governs how long the per-peer/port
// breakdown is kept (see store.RetentionFor).
func New(db *store.DB, retentionDays int) *Scheduler {
	return &Scheduler{db: db, retentionDays: retentionDays}
}

// Run blocks, driving rollups and pruning until ctx is canceled. It rolls up
// once immediately, so anything left over from before a restart is caught up
// at startup rather than a minute later. Progress is tracked by row id in the
// database (store.RunRollup), so tick timing and restarts can't drop or
// double-count rows.
func (s *Scheduler) Run(ctx context.Context) {
	s.rollup()

	tickRollup := time.NewTicker(time.Minute)
	tickPrune := time.NewTicker(time.Hour)
	defer tickRollup.Stop()
	defer tickPrune.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickRollup.C:
			s.rollup()
		case <-tickPrune.C:
			s.prune()
		}
	}
}

func (s *Scheduler) rollup() {
	if _, err := s.db.RunRollup(); err != nil {
		log.Printf("rollupjob: rollup: %v", err)
	}
}

func (s *Scheduler) prune() {
	// Roll up first so pruning flows_recent never races ahead of the rollup.
	s.rollup()
	if err := s.db.Prune(time.Now(), store.RetentionFor(s.retentionDays)); err != nil {
		log.Printf("rollupjob: %v", err)
	}
	if err := s.db.IncrementalVacuum(); err != nil {
		log.Printf("rollupjob: incremental vacuum: %v", err)
	}
}
