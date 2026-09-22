package capture

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	dnsServicePort = 53
	dhcpServerPort = 67
	dhcpClientPort = 68
)

// DecodeResult bundles everything a single packet can produce: a flow
// contribution, an outbound DNS query, and/or a DHCP-announced hostname. Each
// is independently optional (a DHCP packet produces no flow, most packets
// produce no DNS/DHCP event) — using a struct here instead of a long list of
// (value, ok) pairs keeps the call site readable.
type DecodeResult struct {
	Flow    FlowEvent
	HasFlow bool
	DNS     DNSQueryEvent
	HasDNS  bool
	DHCP    DHCPHostnameEvent
	HasDHCP bool
}

// Decoder wraps a reusable gopacket.DecodingLayerParser so repeated packet
// decodes don't allocate a fresh set of layer structs each time.
type Decoder struct {
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	eth   layers.Ethernet
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
		&d.eth, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6,
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
	direction := classifyDirection(srcLocal, dstLocal)

	var localIP, remoteIP net.IP
	var localMAC net.HardwareAddr
	var localPort, remotePort int
	if srcLocal {
		localIP, remoteIP = srcIP, dstIP
		localPort, remotePort = srcPort, dstPort
		localMAC = d.eth.SrcMAC
	} else {
		localIP, remoteIP = dstIP, srcIP
		localPort, remotePort = dstPort, srcPort
		localMAC = d.eth.DstMAC
	}

	ts := pkt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	result.Flow = FlowEvent{
		Key: FlowKey{
			Direction:  direction,
			Proto:      proto,
			LocalIP:    localIP.String(),
			LocalPort:  localPort,
			RemoteIP:   remoteIP.String(),
			RemotePort: remotePort,
		},
		Timestamp:  ts,
		Bytes:      len(pkt.Data),
		IsLocalSrc: srcLocal,
		LocalMAC:   localMAC.String(),
	}
	result.HasFlow = true

	if haveUDP && (srcPort == dnsServicePort || dstPort == dnsServicePort) {
		if q, ok := d.decodeDNSQuery(localIP.String(), ts); ok {
			result.DNS, result.HasDNS = q, true
		}
	}

	return result
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
