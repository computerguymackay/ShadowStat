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

	// convs remembers what's been worked out about each conversation (who
	// started it, its protocol), so later flush windows — which usually see
	// no handshake and only mid-stream payload — keep the answer. Only
	// touched from the flush goroutine.
	convs map[FlowKey]*convState

	macMu   sync.Mutex
	macByIP map[string]string // local IP -> most recently observed MAC, guarded by macMu

	namesMu  sync.Mutex
	namesBuf []PeerNameEvent // DNS-learned peer names between flushes, guarded by namesMu

	dhcpMu  sync.Mutex
	dhcpBuf []DHCPHostnameEvent // buffered DHCP hostname sightings between flushes, guarded by dhcpMu
}

// NewPipeline builds a Pipeline. lan is the configured LAN subnet: addresses
// inside it are LAN hosts, everything else is the internet side of the WAN link.
func NewPipeline(db *store.DB, src Source, lan *net.IPNet, flushEvery time.Duration) *Pipeline {
	return &Pipeline{
		db:         db,
		src:        src,
		agg:        NewAggregator(),
		decoder:    NewDecoder(lan),
		flushEvery: flushEvery,
		hostCache:  make(map[string]int64),
		macByIP:    make(map[string]string),
		convs:      make(map[FlowKey]*convState),
	}
}

// convState is what the pipeline knows about one conversation across flushes.
type convState struct {
	direction   int
	servicePort int
	handshake   bool // direction came from a TCP handshake/ping, not a port guess
	app         string
	conf        int
	touched     int64 // wall-clock unix seconds of the last flush that saw it
}

const (
	// convIdle is how long a conversation is remembered after its last packet.
	convIdle = 10 * 60
	// maxConvs caps the conversation cache. Past it, new conversations are
	// still recorded correctly; they just re-derive their labels each flush.
	maxConvs = 100_000
)

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
				p.rememberMAC(result.Flow)
			}
			if len(result.PeerNames) > 0 {
				p.namesMu.Lock()
				p.namesBuf = append(p.namesBuf, result.PeerNames...)
				p.namesMu.Unlock()
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
			st := p.describe(key, acc, now)
			records = append(records, store.FlowRecord{
				HostID:        hostID,
				Direction:     st.direction,
				Proto:         key.Proto,
				LocalIP:       key.LocalIP,
				LocalPort:     key.LocalPort,
				RemoteIP:      key.RemoteIP,
				RemotePort:    key.RemotePort,
				FirstSeen:     acc.FirstSeen,
				LastSeen:      acc.LastSeen,
				BytesSent:     acc.BytesSent,
				BytesRecv:     acc.BytesRecv,
				PacketsSent:   acc.PacketsSent,
				PacketsRecv:   acc.PacketsRecv,
				ServicePort:   st.servicePort,
				AppProto:      st.app,
				AppConfidence: st.conf,
			})
		}
		if err := p.db.InsertFlows(records); err != nil {
			log.Printf("capture: insert flows: %v", err)
		}
	}

	for key, st := range p.convs {
		if now-st.touched > convIdle {
			delete(p.convs, key)
		}
	}

	p.flushPeerNames()
	p.flushDHCP()
}

// describe works out a conversation's direction, service port and protocol
// from this window's evidence plus anything remembered from earlier windows.
// This is where protocol classification happens — at flush time, once per
// conversation per window, never per packet.
func (p *Pipeline) describe(key FlowKey, acc *FlowAccum, now int64) *convState {
	st, known := p.convs[key]
	if !known {
		st = &convState{direction: store.DirUnknown}
		if len(p.convs) < maxConvs {
			p.convs[key] = st
		}
	}
	st.touched = now

	if !st.handshake {
		st.direction, st.servicePort = inferRoles(key.Proto, key.LocalPort, key.RemotePort, acc.LocalStarted, acc.RemoteStarted)
		st.handshake = acc.LocalStarted != acc.RemoteStarted
	}

	if st.conf < store.ConfPayload {
		if app, conf := classify(key.Proto, st.servicePort, st.direction, acc.LocalPayload, acc.RemotePayload); conf >= st.conf {
			st.app, st.conf = app, conf
		}
	}
	return st
}

func (p *Pipeline) flushPeerNames() {
	p.namesMu.Lock()
	drained := p.namesBuf
	p.namesBuf = nil
	p.namesMu.Unlock()

	if len(drained) == 0 {
		return
	}
	names := make([]store.PeerName, 0, len(drained))
	for _, n := range drained {
		names = append(names, store.PeerName{IP: n.IP, Name: n.Name, LastSeen: n.Timestamp.Unix()})
	}
	if err := p.db.UpsertPeerNames(names); err != nil {
		log.Printf("capture: upsert peer names: %v", err)
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

func (p *Pipeline) rememberMAC(flow FlowEvent) {
	if flow.LocalMAC == "" {
		return
	}
	p.macMu.Lock()
	p.macByIP[flow.Key.LocalIP] = flow.LocalMAC
	p.macMu.Unlock()
}
