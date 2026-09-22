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

	hostCache       map[string]int64    // local IP -> host_id, populated once and never cleared
	bumpedThisFlush map[string]struct{} // local IPs already touched (last_seen/MAC) in the current flush() call

	macMu   sync.Mutex
	macByIP map[string]string // local IP -> most recently observed MAC, guarded by macMu

	dnsMu  sync.Mutex
	dnsBuf []DNSQueryEvent // buffered DNS queries between flushes, guarded by dnsMu

	dhcpMu  sync.Mutex
	dhcpBuf []DHCPHostnameEvent // buffered DHCP hostname sightings between flushes, guarded by dhcpMu
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
		macByIP:    make(map[string]string),
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
			result := p.decoder.Decode(pkt)

			if result.HasFlow {
				p.agg.Add(result.Flow)
				if result.Flow.LocalMAC != "" {
					p.macMu.Lock()
					p.macByIP[result.Flow.Key.LocalIP] = result.Flow.LocalMAC
					p.macMu.Unlock()
				}
			}
			if result.HasDNS {
				p.dnsMu.Lock()
				p.dnsBuf = append(p.dnsBuf, result.DNS)
				p.dnsMu.Unlock()
			}
			if result.HasDHCP {
				p.dhcpMu.Lock()
				p.dhcpBuf = append(p.dhcpBuf, result.DHCP)
				p.dhcpMu.Unlock()
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
	now := time.Now().Unix()
	p.bumpedThisFlush = make(map[string]struct{})

	drained := p.agg.Drain()
	if len(drained) > 0 {
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

	p.flushDNS(now)
	p.flushDHCP()
}

func (p *Pipeline) flushDNS(now int64) {
	p.dnsMu.Lock()
	drained := p.dnsBuf
	p.dnsBuf = nil
	p.dnsMu.Unlock()

	if len(drained) == 0 {
		return
	}

	records := make([]store.DNSQueryRecord, 0, len(drained))
	for _, q := range drained {
		hostID, err := p.resolveHost(q.LocalIP, now)
		if err != nil {
			log.Printf("capture: resolve host %s: %v", q.LocalIP, err)
			continue
		}
		records = append(records, store.DNSQueryRecord{
			HostID: hostID,
			QName:  q.QName,
			QType:  int(q.QType),
			TS:     q.Timestamp.Unix(),
		})
	}
	if err := p.db.InsertDNSQueries(records); err != nil {
		log.Printf("capture: insert dns queries: %v", err)
	}
}

func (p *Pipeline) flushDHCP() {
	p.dhcpMu.Lock()
	drained := p.dhcpBuf
	p.dhcpBuf = nil
	p.dhcpMu.Unlock()

	for _, ev := range drained {
		if ev.MAC == "" || ev.Hostname == "" {
			continue
		}
		if err := p.db.UpsertDHCPHostname(ev.MAC, ev.Hostname, ev.Timestamp.Unix()); err != nil {
			log.Printf("capture: upsert dhcp hostname for %s: %v", ev.MAC, err)
		}
	}
}

// resolveHost returns the host_id for a local IP. The very first time an IP
// is seen it's upserted (creating the row); on every later call within the
// process's lifetime the id comes from hostCache, but last_seen (and, if a
// MAC has been learned since, mac_address) are still refreshed — capped to
// once per flush() call via bumpedThisFlush, so a host with several
// concurrent flows in one flush doesn't trigger redundant writes.
func (p *Pipeline) resolveHost(ip string, seenAt int64) (int64, error) {
	id, cached := p.hostCache[ip]

	if _, done := p.bumpedThisFlush[ip]; done {
		return id, nil // already fully handled (last_seen bumped, MAC set) this flush
	}
	p.bumpedThisFlush[ip] = struct{}{}

	if !cached {
		newID, err := p.db.UpsertHost(ip, seenAt)
		if err != nil {
			return 0, err
		}
		id = newID
		p.hostCache[ip] = id
	} else if _, err := p.db.UpsertHost(ip, seenAt); err != nil {
		log.Printf("capture: bump last_seen for %s: %v", ip, err)
	}

	if mac := p.lookupMAC(ip); mac != "" {
		if err := p.db.SetHostMAC(id, mac); err != nil {
			log.Printf("capture: set host MAC for %s: %v", ip, err)
		}
	}
	return id, nil
}

func (p *Pipeline) lookupMAC(ip string) string {
	p.macMu.Lock()
	defer p.macMu.Unlock()
	return p.macByIP[ip]
}
