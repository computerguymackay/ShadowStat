// Package capture ingests raw packets from a network interface, decodes them
// into flow events, and aggregates them in memory for periodic flushing to
// storage. The Source interface is the seam that keeps this pluggable for
// future sFlow/NetFlow collectors alongside the current live AF_PACKET capture.
package capture

import (
	"context"
	"time"
)

// RawPacket is one captured frame, timestamped by the source.
type RawPacket struct {
	Data      []byte
	Timestamp time.Time
}

// Source produces a stream of raw packets. Implementations must never block
// their internal read loop waiting for a slow consumer — drop and count instead.
type Source interface {
	// Packets starts the source (if not already running) and returns a channel
	// of packets and a channel of non-fatal errors. Both channels close when
	// ctx is canceled and the source has fully shut down.
	Packets(ctx context.Context) (<-chan RawPacket, <-chan error)
	// Close releases the underlying handle. Safe to call after ctx cancellation.
	Close() error
}

// FlowKey canonicalizes a flow's identity for aggregation.
type FlowKey struct {
	Direction  int
	Proto      int
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
}

// FlowEvent is one decoded packet's contribution to a flow.
type FlowEvent struct {
	Key        FlowKey
	Timestamp  time.Time
	Bytes      int
	IsLocalSrc bool // true if the packet's source side is the LAN-local address
}

// classifyDirection determines a packet's direction from which side(s) of the
// 5-tuple fall inside the configured LAN subnet. Both-local and both-remote
// packets shouldn't reach here given the BPF filter, but are defensively
// classified as inter-VLAN so they're visible rather than dropped.
func classifyDirection(srcLocal, dstLocal bool) int {
	switch {
	case srcLocal && !dstLocal:
		return 0 // LAN -> WAN
	case !srcLocal && dstLocal:
		return 1 // WAN -> LAN
	default:
		return 2 // inter-VLAN (both local or both remote)
	}
}
