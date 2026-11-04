package capture

import (
	"testing"
	"time"
)

func TestAggregatorAddAndDrain(t *testing.T) {
	agg := NewAggregator()
	key := FlowKey{Proto: 6, LocalIP: "192.168.1.50", LocalPort: 1234, RemoteIP: "1.2.3.4", RemotePort: 443}

	agg.Add(FlowEvent{Key: key, Timestamp: time.Unix(1000, 0), Bytes: 100, IsLocalSrc: true})
	agg.Add(FlowEvent{Key: key, Timestamp: time.Unix(1005, 0), Bytes: 50, IsLocalSrc: false})
	agg.Add(FlowEvent{Key: key, Timestamp: time.Unix(1010, 0), Bytes: 200, IsLocalSrc: true})

	drained := agg.Drain()
	if len(drained) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(drained))
	}
	acc := drained[key]
	if acc.BytesSent != 300 {
		t.Errorf("bytes sent = %d, want 300", acc.BytesSent)
	}
	if acc.BytesRecv != 50 {
		t.Errorf("bytes recv = %d, want 50", acc.BytesRecv)
	}
	if acc.PacketsSent != 2 || acc.PacketsRecv != 1 {
		t.Errorf("packets = %d sent / %d recv, want 2/1", acc.PacketsSent, acc.PacketsRecv)
	}
	if acc.FirstSeen != 1000 || acc.LastSeen != 1010 {
		t.Errorf("first/last seen = %d/%d, want 1000/1010", acc.FirstSeen, acc.LastSeen)
	}

	// Drain should leave the aggregator empty for the next cycle.
	if empty := agg.Drain(); len(empty) != 0 {
		t.Errorf("expected empty drain after previous drain, got %d entries", len(empty))
	}
}

func TestAggregatorRecordsWhoStartedAndPayloadSnippets(t *testing.T) {
	agg := NewAggregator()
	out := FlowKey{Proto: 6, LocalIP: "192.168.1.50", LocalPort: 50000, RemoteIP: "1.2.3.4", RemotePort: 443}
	in := FlowKey{Proto: 6, LocalIP: "192.168.1.50", LocalPort: 22, RemoteIP: "5.6.7.8", RemotePort: 40000}
	ts := time.Unix(1000, 0)

	big := make([]byte, 1000)
	big[0] = 0x16
	agg.Add(FlowEvent{Key: out, Timestamp: ts, Bytes: 60, IsLocalSrc: true, SYN: true})
	agg.Add(FlowEvent{Key: out, Timestamp: ts, Bytes: 60, IsLocalSrc: false, SYN: true, ACK: true})
	agg.Add(FlowEvent{Key: out, Timestamp: ts, Bytes: 1000, IsLocalSrc: true, ACK: true, Payload: big})
	agg.Add(FlowEvent{Key: out, Timestamp: ts, Bytes: 100, IsLocalSrc: true, ACK: true, Payload: []byte("second")})
	// Inbound connection: only the SYN-ACK from the LAN host was seen.
	agg.Add(FlowEvent{Key: in, Timestamp: ts, Bytes: 60, IsLocalSrc: true, SYN: true, ACK: true})

	drained := agg.Drain()
	o := drained[out]
	if !o.LocalStarted || o.RemoteStarted {
		t.Errorf("outbound: local=%v remote=%v, want local only", o.LocalStarted, o.RemoteStarted)
	}
	if len(o.LocalPayload) != snippetLen || o.LocalPayload[0] != 0x16 {
		t.Errorf("local snippet len=%d, want the first payload truncated to %d", len(o.LocalPayload), snippetLen)
	}
	if o.RemotePayload != nil {
		t.Error("remote sent no payload, snippet should be nil")
	}
	big[0] = 0 // the snippet must be a copy, not alias the packet buffer
	if o.LocalPayload[0] != 0x16 {
		t.Error("snippet aliases the packet buffer")
	}

	i := drained[in]
	if i.LocalStarted || !i.RemoteStarted {
		t.Errorf("inbound: local=%v remote=%v, want remote only", i.LocalStarted, i.RemoteStarted)
	}
}
