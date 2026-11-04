package capture

import "sync"

// snippetLen is how many payload bytes are kept per side of a flow for
// protocol identification. Enough for every signature in classify.go.
const snippetLen = 256

// FlowAccum accumulates a single flow's stats between flushes.
type FlowAccum struct {
	FirstSeen   int64
	LastSeen    int64
	BytesSent   int64
	BytesRecv   int64
	PacketsSent int64
	PacketsRecv int64

	// Evidence of who started the conversation, from a TCP SYN / SYN-ACK or
	// an ICMP echo request seen in this flush window.
	LocalStarted  bool
	RemoteStarted bool

	// The first payload bytes each side sent in this flush window (at most
	// snippetLen), for protocol identification at flush time.
	LocalPayload  []byte
	RemotePayload []byte
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

// Add records one flow event's contribution. Kept lock-minimal: no I/O under
// the lock, and no parsing — at most one bounded copy per side per window.
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

	// A SYN (or ping) comes from the side starting the conversation; a
	// SYN-ACK comes from the other side.
	switch {
	case (evt.SYN && !evt.ACK) || evt.EchoRequest:
		acc.markStarted(evt.IsLocalSrc)
	case evt.SYN && evt.ACK:
		acc.markStarted(!evt.IsLocalSrc)
	}

	if len(evt.Payload) > 0 {
		if evt.IsLocalSrc && acc.LocalPayload == nil {
			acc.LocalPayload = snippet(evt.Payload)
		} else if !evt.IsLocalSrc && acc.RemotePayload == nil {
			acc.RemotePayload = snippet(evt.Payload)
		}
	}
}

func snippet(b []byte) []byte {
	return append([]byte(nil), b[:min(len(b), snippetLen)]...)
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

func (acc *FlowAccum) markStarted(byLocal bool) {
	if byLocal {
		acc.LocalStarted = true
	} else {
		acc.RemoteStarted = true
	}
}
