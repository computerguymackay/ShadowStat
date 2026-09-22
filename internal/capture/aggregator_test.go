package capture

import (
	"testing"
	"time"
)

func TestAggregatorAddAndDrain(t *testing.T) {
	agg := NewAggregator()
	key := FlowKey{Direction: 0, Proto: 6, LocalIP: "192.168.1.50", LocalPort: 1234, RemoteIP: "1.2.3.4", RemotePort: 443}

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
