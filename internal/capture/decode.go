package capture

import (
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	dnsServicePort = 53
	dhcpServerPort = 67
	dhcpClientPort = 68

	// maxNamesPerAnswer bounds how many A records one DNS answer contributes.
	maxNamesPerAnswer = 16
)

// DecodeResult bundles everything a single packet can produce: a flow
// contribution, hostname -> IP mappings from a DNS answer, and/or a
// DHCP-announced hostname. Each is independently optional.
type DecodeResult struct {
	Flow      FlowEvent
	HasFlow   bool
	PeerNames []PeerNameEvent
	DHCP      DHCPHostnameEvent
	HasDHCP   bool
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

// NewDecoder creates a Decoder that treats addresses inside lan as the LAN
// side and everything else as the internet (WAN) side.
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

// Decode parses a raw packet and reports whatever it finds. Only packets
// crossing the WAN boundary (exactly one side inside the LAN subnet) become
// flows. DNS answers and DHCP hostnames are read from any packet, since the
// LAN's resolver and DHCP server are usually on the LAN itself.
func (d *Decoder) Decode(pkt RawPacket) DecodeResult {
	// Partial decodes are expected (IgnoreUnsupported) and still populate
	// d.decoded with whatever layers *were* recognized, so the error is
	// deliberately ignored here; absence of a usable IP layer is checked below.
	_ = d.parser.DecodeLayers(pkt.Data, &d.decoded)

	var (
		haveIP, haveUDP  bool
		srcIP, dstIP     net.IP
		proto            int
		srcPort, dstPort int
		syn, ack, echo   bool
		payload          []byte
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
			syn, ack = d.tcp.SYN, d.tcp.ACK
			payload = d.tcp.Payload
		case layers.LayerTypeUDP:
			haveUDP = true
			srcPort, dstPort = int(d.udp.SrcPort), int(d.udp.DstPort)
			payload = d.udp.Payload
		case layers.LayerTypeICMPv4:
			echo = d.icmp4.TypeCode.Type() == layers.ICMPv4TypeEchoRequest
		case layers.LayerTypeICMPv6:
			echo = d.icmp6.TypeCode.Type() == layers.ICMPv6TypeEchoRequest
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
	// meaningful per-host flow to record.
	if srcIP.IsUnspecified() || dstIP.Equal(net.IPv4bcast) {
		return result
	}

	ts := pkt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	if haveUDP && srcPort == dnsServicePort {
		result.PeerNames = d.decodeDNSAnswers(ts)
	}

	srcLocal := d.lan.Contains(srcIP)
	dstLocal := d.lan.Contains(dstIP)
	if srcLocal == dstLocal {
		// Both LAN (not WAN traffic) or neither (no LAN host to attribute it to).
		return result
	}

	evt := FlowEvent{
		Timestamp:   ts,
		Bytes:       len(pkt.Data),
		IsLocalSrc:  srcLocal,
		SYN:         syn,
		ACK:         ack,
		EchoRequest: echo,
		Payload:     payload,
	}
	if srcLocal {
		evt.Key = FlowKey{Proto: proto, LocalIP: srcIP.String(), LocalPort: srcPort, RemoteIP: dstIP.String(), RemotePort: dstPort}
		evt.LocalMAC = d.eth.SrcMAC.String()
	} else {
		evt.Key = FlowKey{Proto: proto, LocalIP: dstIP.String(), LocalPort: dstPort, RemoteIP: srcIP.String(), RemotePort: srcPort}
		evt.LocalMAC = d.eth.DstMAC.String()
	}
	result.Flow, result.HasFlow = evt, true
	return result
}

// decodeDNSAnswers decodes the UDP payload as a DNS response and returns one
// mapping per A record, named after the question (what the user actually
// looked up, rather than the final CNAME target).
func (d *Decoder) decodeDNSAnswers(ts time.Time) []PeerNameEvent {
	if err := d.dns.DecodeFromBytes(d.udp.Payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	if !d.dns.QR || d.dns.ResponseCode != layers.DNSResponseCodeNoErr || len(d.dns.Questions) == 0 {
		return nil
	}
	name := strings.TrimSuffix(strings.ToLower(string(d.dns.Questions[0].Name)), ".")
	if name == "" {
		return nil
	}
	var out []PeerNameEvent
	for _, a := range d.dns.Answers {
		if a.Type != layers.DNSTypeA || a.IP == nil {
			continue
		}
		out = append(out, PeerNameEvent{IP: a.IP.String(), Name: name, Timestamp: ts})
		if len(out) == maxNamesPerAnswer {
			break
		}
	}
	return out
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
