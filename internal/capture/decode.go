package capture

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"ShadowStat/internal/store"
)

const (
	dnsServicePort = 53
	dhcpServerPort = 67
	dhcpClientPort = 68
)

// DecodeResult bundles everything a single packet can produce: a flow
// contribution (or two — see Flow2), an outbound DNS query, and/or a
// DHCP-announced hostname. Each is independently optional (a DHCP packet
// produces no flow, most packets produce no DNS/DHCP event) — using a struct
// here instead of a long list of (value, ok) pairs keeps the call site readable.
//
// A LAN-to-LAN packet (both source and destination inside the configured
// subnet) produces TWO flow events, one per host's perspective — Flow from
// the initiator's side, Flow2 from the receiver's side. Without this, only
// whichever host happened to be the packet's source would ever see the
// traffic in its own stats/detectors; the destination side (e.g. this
// machine, when something on the LAN is scanning or otherwise contacting it)
// would be invisible.
type DecodeResult struct {
	Flow     FlowEvent
	HasFlow  bool
	Flow2    FlowEvent
	HasFlow2 bool
	DNS      DNSQueryEvent
	HasDNS   bool
	DHCP     DHCPHostnameEvent
	HasDHCP  bool
}

// Decoder wraps a reusable gopacket.DecodingLayerParser so repeated packet
// decodes don't allocate a fresh set of layer structs each time.
type Decoder struct {
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	eth   layers.Ethernet
	dot1q layers.Dot1Q // 802.1Q VLAN tag; gopacket auto-chains through this (EthernetType 0x8100 is
	// registered to LayerTypeDot1Q in its own layer-type table), so just
	// registering the decoder here is enough — no manual dispatch needed,
	// unlike DNS/DHCP below which key off a UDP port instead of an EtherType.
	ip4   layers.IPv4
	ip6   layers.IPv6
	tcp   layers.TCP
	udp   layers.UDP
	icmp4 layers.ICMPv4
	icmp6 layers.ICMPv6
	dns   layers.DNS    // decoded manually below; gopacket doesn't auto-chain UDP->DNS
	dhcp  layers.DHCPv4 // decoded manually below, same reason

	lan *net.IPNet
}

// NewDecoder creates a Decoder that classifies flows against lan.
func NewDecoder(lan *net.IPNet) *Decoder {
	d := &Decoder{lan: lan}
	d.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&d.eth, &d.dot1q, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6,
	)
	// A packet missing a layer we didn't register a decoder for (e.g. an
	// unsupported next-header) should not abort decoding of the layers found so far.
	d.parser.IgnoreUnsupported = true
	return d
}

// Decode parses a raw packet and reports whatever it finds. Broadcast/
// unspecified-address traffic (DHCP DISCOVER/OFFER) never becomes a flow —
// it has no meaningful "host" IP — but is still checked for a DHCP hostname.
func (d *Decoder) Decode(pkt RawPacket) DecodeResult {
	// Partial decodes are expected (IgnoreUnsupported) and still populate
	// d.decoded with whatever layers *were* recognized, so the error is
	// deliberately ignored here; absence of a usable IP layer is checked below.
	_ = d.parser.DecodeLayers(pkt.Data, &d.decoded)

	var (
		haveIP           bool
		haveUDP          bool
		srcIP, dstIP     net.IP
		proto            int
		srcPort, dstPort int
	)

	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			haveIP = true
			srcIP, dstIP = d.ip4.SrcIP, d.ip4.DstIP
			proto = int(d.ip4.Protocol)
		case layers.LayerTypeIPv6:
			haveIP = true
			srcIP, dstIP = d.ip6.SrcIP, d.ip6.DstIP
			proto = int(d.ip6.NextHeader)
		case layers.LayerTypeTCP:
			srcPort, dstPort = int(d.tcp.SrcPort), int(d.tcp.DstPort)
		case layers.LayerTypeUDP:
			haveUDP = true
			srcPort, dstPort = int(d.udp.SrcPort), int(d.udp.DstPort)
		}
	}

	var result DecodeResult
	if !haveIP {
		return result
	}
	// Ports default to 0 for ICMP/other non-port-bearing protocols.

	if haveUDP && (srcPort == dhcpClientPort || dstPort == dhcpServerPort) {
		if ev, ok := d.decodeDHCPHostname(pkt.Timestamp); ok {
			result.DHCP, result.HasDHCP = ev, true
		}
	}

	// DHCP DISCOVER/REQUEST traffic (src 0.0.0.0 and/or broadcast dst) has no
	// meaningful per-host flow to record — skip flow/DNS handling for it.
	if srcIP.IsUnspecified() || dstIP.Equal(net.IPv4bcast) {
		return result
	}

	srcLocal := d.lan.Contains(srcIP)
	dstLocal := d.lan.Contains(dstIP)

	ts := pkt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	bytes := len(pkt.Data)

	switch {
	case srcLocal && dstLocal:
		// LAN-to-LAN: record from both hosts' perspectives so the receiving
		// side (e.g. this machine, if it's the one being contacted/scanned by
		// another LAN device) shows up in its own stats and detectors too.
		result.Flow = buildFlowEvent(store.DirLANOut, proto, srcIP, srcPort, dstIP, dstPort, d.eth.SrcMAC, ts, bytes, true)
		result.HasFlow = true
		result.Flow2 = buildFlowEvent(store.DirLANIn, proto, dstIP, dstPort, srcIP, srcPort, d.eth.DstMAC, ts, bytes, false)
		result.HasFlow2 = true

		if haveUDP && (srcPort == dnsServicePort || dstPort == dnsServicePort) {
			if q, ok := d.decodeDNSQuery(srcIP.String(), ts); ok {
				result.DNS, result.HasDNS = q, true
			}
		}

	case srcLocal: // LAN -> WAN
		result.Flow = buildFlowEvent(store.DirLANToWAN, proto, srcIP, srcPort, dstIP, dstPort, d.eth.SrcMAC, ts, bytes, true)
		result.HasFlow = true
		if haveUDP && (srcPort == dnsServicePort || dstPort == dnsServicePort) {
			if q, ok := d.decodeDNSQuery(srcIP.String(), ts); ok {
				result.DNS, result.HasDNS = q, true
			}
		}

	case dstLocal: // WAN -> LAN
		result.Flow = buildFlowEvent(store.DirWANToLAN, proto, dstIP, dstPort, srcIP, srcPort, d.eth.DstMAC, ts, bytes, false)
		result.HasFlow = true
		if haveUDP && (srcPort == dnsServicePort || dstPort == dnsServicePort) {
			if q, ok := d.decodeDNSQuery(dstIP.String(), ts); ok {
				result.DNS, result.HasDNS = q, true
			}
		}

	default:
		// Neither side is in the configured LAN subnet — shouldn't happen
		// given the BPF filter, but there's no sensible "local" host to
		// attribute a flow to, so drop it rather than fabricate one.
	}

	return result
}

// buildFlowEvent constructs a FlowEvent from the perspective of localIP.
func buildFlowEvent(direction, proto int, localIP net.IP, localPort int, remoteIP net.IP, remotePort int, localMAC net.HardwareAddr, ts time.Time, bytes int, isLocalSrc bool) FlowEvent {
	return FlowEvent{
		Key: FlowKey{
			Direction:  direction,
			Proto:      proto,
			LocalIP:    localIP.String(),
			LocalPort:  localPort,
			RemoteIP:   remoteIP.String(),
			RemotePort: remotePort,
		},
		Timestamp:  ts,
		Bytes:      bytes,
		IsLocalSrc: isLocalSrc,
		LocalMAC:   localMAC.String(),
	}
}

// decodeDNSQuery manually decodes the UDP payload as DNS — gopacket's
// DecodingLayerParser chain doesn't auto-dispatch UDP->DNS in this version, so
// this is invoked directly rather than registered on the parser. Only actual
// queries (QR=false) with at least one question are reported, so a query and
// its matching response aren't both counted.
func (d *Decoder) decodeDNSQuery(localIP string, ts time.Time) (DNSQueryEvent, bool) {
	if err := d.dns.DecodeFromBytes(d.udp.Payload, gopacket.NilDecodeFeedback); err != nil {
		return DNSQueryEvent{}, false
	}
	if d.dns.QR || len(d.dns.Questions) == 0 {
		return DNSQueryEvent{}, false
	}
	q := d.dns.Questions[0]
	return DNSQueryEvent{
		LocalIP:   localIP,
		QName:     string(q.Name),
		QType:     uint16(q.Type),
		Timestamp: ts,
	}, true
}

// decodeDHCPHostname manually decodes the UDP payload as DHCPv4 — same
// no-auto-chaining situation as DNS. Only client-originated messages
// (DISCOVER/REQUEST) carrying option 12 (Hostname) produce an event; the
// client's hardware address (not its as-yet-unassigned IP) is the key.
func (d *Decoder) decodeDHCPHostname(ts time.Time) (DHCPHostnameEvent, bool) {
	if err := d.dhcp.DecodeFromBytes(d.udp.Payload, gopacket.NilDecodeFeedback); err != nil {
		return DHCPHostnameEvent{}, false
	}
	if d.dhcp.Operation != layers.DHCPOpRequest {
		return DHCPHostnameEvent{}, false // server->client message, not client-originated
	}
	for _, opt := range d.dhcp.Options {
		if opt.Type == layers.DHCPOptHostname && len(opt.Data) > 0 {
			if ts.IsZero() {
				ts = time.Now()
			}
			return DHCPHostnameEvent{
				MAC:       d.dhcp.ClientHWAddr.String(),
				Hostname:  string(opt.Data),
				Timestamp: ts,
			}, true
		}
	}
	return DHCPHostnameEvent{}, false
}
