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

// FlowKey identifies one conversation from the LAN host's side. There is
// deliberately no direction in it: both directions of a conversation land in
// the same entry (as sent and received bytes), and who started it is worked
// out at flush time from the evidence in FlowAccum.
type FlowKey struct {
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
	IsLocalSrc bool   // true if the packet was sent by the LAN host
	LocalMAC   string // Ethernet MAC of the LAN-local side, for device identification

	SYN, ACK    bool   // TCP flags on this packet
	EchoRequest bool   // ICMP echo request ("ping")
	Payload     []byte // L4 payload; aliases the packet buffer, so copy before keeping it
}

// PeerNameEvent is one hostname -> IPv4 mapping seen in a DNS answer, used
// to show remote peers by name.
type PeerNameEvent struct {
	IP        string
	Name      string
	Timestamp time.Time
}

// DHCPHostnameEvent is a hostname a LAN client announced during DHCP
// negotiation (option 12), used to give hosts human-readable names. Keyed by
// MAC rather than IP since a client typically has no IP yet at DISCOVER time.
type DHCPHostnameEvent struct {
	MAC       string
	Hostname  string
	Timestamp time.Time
}
