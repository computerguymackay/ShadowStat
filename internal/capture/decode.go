package capture

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const dnsPort = 53

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
	dns   layers.DNS // decoded manually below; gopacket doesn't auto-chain UDP->DNS

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

// Decode parses a raw packet into a FlowEvent, and — if the packet is an
// outbound DNS query — also a DNSQueryEvent. flowOK is false for packets that
// aren't IPv4/IPv6+TCP/UDP/ICMP (nothing meaningful to aggregate). dnsOK is
// true only for UDP/53 packets carrying an actual query (not a response).
func (d *Decoder) Decode(pkt RawPacket) (flow FlowEvent, flowOK bool, dns DNSQueryEvent, dnsOK bool) {
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

	if !haveIP {
		return FlowEvent{}, false, DNSQueryEvent{}, false
	}
	// Ports default to 0 for ICMP/other non-port-bearing protocols.

	srcLocal := d.lan.Contains(srcIP)
	dstLocal := d.lan.Contains(dstIP)
	direction := classifyDirection(srcLocal, dstLocal)

	var localIP, remoteIP net.IP
	var localPort, remotePort int
	if srcLocal {
		localIP, remoteIP = srcIP, dstIP
		localPort, remotePort = srcPort, dstPort
	} else {
		localIP, remoteIP = dstIP, srcIP
		localPort, remotePort = dstPort, srcPort
	}

	ts := pkt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	flow = FlowEvent{
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
	}

	if haveUDP && (srcPort == dnsPort || dstPort == dnsPort) {
		if q, ok := d.decodeDNSQuery(localIP.String(), ts); ok {
			dns, dnsOK = q, true
		}
	}

	return flow, true, dns, dnsOK
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
