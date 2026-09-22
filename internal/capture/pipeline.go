package capture

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"ShadowStat/internal/store"
)

// Pipeline wires a Source through decoding and aggregation to periodic,
// batched writes against the store.
type Pipeline struct {
	db         *store.DB
	src        Source
	agg        *Aggregator
	decoder    *Decoder
	flushEvery time.Duration

	hostCache map[string]int64 // local IP -> host_id; owned solely by the flush goroutine
}

// NewPipeline builds a Pipeline. lan is the configured LAN subnet, used both to
// build the decoder's direction classification and (by the caller) to compile
// the BPF filter applied to src.
func NewPipeline(db *store.DB, src Source, lan *net.IPNet, flushEvery time.Duration) *Pipeline {
	return &Pipeline{
		db:         db,
		src:        src,
		agg:        NewAggregator(),
		decoder:    NewDecoder(lan),
		flushEvery: flushEvery,
		hostCache:  make(map[string]int64),
	}
}

// Run starts the capture pipeline and blocks until ctx is canceled, performing
// a final flush before returning. Safe to run in its own goroutine.
func (p *Pipeline) Run(ctx context.Context) error {
	packets, errs := p.src.Packets(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for pkt := range packets {
			if evt, ok := p.decoder.Decode(pkt); ok {
				p.agg.Add(evt)
			}
		}
	}()

	ticker := time.NewTicker(p.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.flush()
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			log.Printf("capture: source error: %v", err)
		case <-ctx.Done():
			wg.Wait() // decode goroutine exits once packets channel closes
			p.flush() // final flush with whatever was captured before shutdown
			return p.src.Close()
		}
	}
}

func (p *Pipeline) flush() {
	drained := p.agg.Drain()
	if len(drained) == 0 {
		return
	}

	now := time.Now().Unix()
	records := make([]store.FlowRecord, 0, len(drained))
	for key, acc := range drained {
		hostID, err := p.resolveHost(key.LocalIP, now)
		if err != nil {
			log.Printf("capture: resolve host %s: %v", key.LocalIP, err)
			continue
		}
		records = append(records, store.FlowRecord{
			HostID:      hostID,
			Direction:   key.Direction,
			Proto:       key.Proto,
			LocalIP:     key.LocalIP,
			LocalPort:   key.LocalPort,
			RemoteIP:    key.RemoteIP,
			RemotePort:  key.RemotePort,
			FirstSeen:   acc.FirstSeen,
			LastSeen:    acc.LastSeen,
			BytesSent:   acc.BytesSent,
			BytesRecv:   acc.BytesRecv,
			PacketsSent: acc.PacketsSent,
			PacketsRecv: acc.PacketsRecv,
		})
	}

	if err := p.db.InsertFlows(records); err != nil {
		log.Printf("capture: insert flows: %v", err)
	}
}

// resolveHost returns the host_id for a local IP, upserting the hosts table and
// caching the result in-process to avoid a DB round trip per flow.
func (p *Pipeline) resolveHost(ip string, seenAt int64) (int64, error) {
	if id, ok := p.hostCache[ip]; ok {
		return id, nil
	}
	id, err := p.db.UpsertHost(ip, seenAt)
	if err != nil {
		return 0, err
	}
	p.hostCache[ip] = id
	return id, nil
}
