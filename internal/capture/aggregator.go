package capture

import "sync"

// FlowAccum accumulates a single flow's stats between flushes.
type FlowAccum struct {
	FirstSeen   int64
	LastSeen    int64
	BytesSent   int64
	BytesRecv   int64
	PacketsSent int64
	PacketsRecv int64
}

// Aggregator buffers flow data in memory, keyed by FlowKey, between periodic
// flushes to storage. Expected cardinality is a home/small-office LAN mirrored
// WAN link — low thousands of concurrent flows — so a single mutex-guarded map
// is simple and sufficient; don't shard unless profiling shows contention.
type Aggregator struct {
	mu    sync.Mutex
	table map[FlowKey]*FlowAccum
}

// NewAggregator creates an empty Aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{table: make(map[FlowKey]*FlowAccum)}
}

// Add records one flow event's contribution. Kept lock-minimal: no I/O under the lock.
func (a *Aggregator) Add(evt FlowEvent) {
	ts := evt.Timestamp.Unix()

	a.mu.Lock()
	defer a.mu.Unlock()

	acc, ok := a.table[evt.Key]
	if !ok {
		acc = &FlowAccum{FirstSeen: ts, LastSeen: ts}
		a.table[evt.Key] = acc
	}
	if ts < acc.FirstSeen {
		acc.FirstSeen = ts
	}
	if ts > acc.LastSeen {
		acc.LastSeen = ts
	}
	if evt.IsLocalSrc {
		acc.BytesSent += int64(evt.Bytes)
		acc.PacketsSent++
	} else {
		acc.BytesRecv += int64(evt.Bytes)
		acc.PacketsRecv++
	}
}

// Drain atomically swaps in a fresh empty table and returns the previous one,
// so flush never blocks ingestion for longer than a pointer swap.
func (a *Aggregator) Drain() map[FlowKey]*FlowAccum {
	a.mu.Lock()
	defer a.mu.Unlock()

	drained := a.table
	a.table = make(map[FlowKey]*FlowAccum)
	return drained
}
