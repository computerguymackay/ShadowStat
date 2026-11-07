package capture

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func synthTCPPacket(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	return synthTCPFlags(t, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, true, false, payload)
}

func synthTCPFlags(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, syn, ack bool, payload []byte) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1,
		SYN:     syn,
		ACK:     ack,
		Window:  1024,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize test packet: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

func TestDecodeClassifiesLANToWAN(t *testing.T) {
	_, lan, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(lan)

	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	data := synthTCPPacket(t, srcMAC, dstMAC,
		net.ParseIP("192.168.1.50"), net.ParseIP("93.184.216.34"),
		54321, 443, []byte("hello"))

	res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})
	if !res.HasFlow {
		t.Fatal("expected decode to succeed")
	}
	if len(res.PeerNames) != 0 {
		t.Error("expected no DNS names from a plain TCP packet")
	}

	evt := res.Flow
	if !evt.SYN || evt.ACK {
		t.Errorf("flags SYN=%v ACK=%v, want SYN only", evt.SYN, evt.ACK)
	}
	if string(evt.Payload) != "hello" {
		t.Errorf("payload = %q, want %q", evt.Payload, "hello")
	}
	if evt.Key.Proto != int(layers.IPProtocolTCP) {
		t.Errorf("proto = %d, want %d", evt.Key.Proto, layers.IPProtocolTCP)
	}
	if evt.Key.LocalIP != "192.168.1.50" {
		t.Errorf("local ip = %s, want 192.168.1.50", evt.Key.LocalIP)
	}
	if evt.Key.RemoteIP != "93.184.216.34" {
		t.Errorf("remote ip = %s, want 93.184.216.34", evt.Key.RemoteIP)
	}
	if evt.Key.LocalPort != 54321 || evt.Key.RemotePort != 443 {
		t.Errorf("ports = %d/%d, want 54321/443", evt.Key.LocalPort, evt.Key.RemotePort)
	}
	if !evt.IsLocalSrc {
		t.Error("expected IsLocalSrc = true")
	}
	if evt.Bytes != len(data) {
		t.Errorf("bytes = %d, want %d", evt.Bytes, len(data))
	}
	if evt.LocalMAC != srcMAC.String() {
		t.Errorf("local MAC = %q, want %q", evt.LocalMAC, srcMAC.String())
	}
}

func synthDNSAnswerPacket(t *testing.T, srcIP, dstIP net.IP, qname string, answers ...net.IP) []byte {
	t.Helper()
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:10")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:11")

	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(dnsServicePort), DstPort: layers.UDPPort(51000)}
	dns := &layers.DNS{
		ID: 1234, QR: true, OpCode: layers.DNSOpCodeQuery, RD: true, RA: true,
		Questions: []layers.DNSQuestion{{Name: []byte(qname), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	}
	for _, a := range answers {
		dns.Answers = append(dns.Answers, layers.DNSResourceRecord{
			Name: []byte(qname), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: a,
		})
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		t.Fatalf("serialize test DNS packet: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// The LAN's resolver is usually the router, so the answer that names a
// remote peer is LAN-to-LAN traffic: no flow, but names are still learned.
func TestDecodeLearnsPeerNamesFromDNSAnswers(t *testing.T) {
	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	d := NewDecoder(lan)

	data := synthDNSAnswerPacket(t, net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.50"),
		"Example.COM", net.ParseIP("93.184.216.34"), net.ParseIP("93.184.216.35"))
	res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})

	if res.HasFlow {
		t.Error("expected no flow for LAN-to-LAN DNS traffic")
	}
	if len(res.PeerNames) != 2 {
		t.Fatalf("peer names = %+v, want 2", res.PeerNames)
	}
	if res.PeerNames[0].IP != "93.184.216.34" || res.PeerNames[0].Name != "example.com" {
		t.Errorf("peer name = %+v, want 93.184.216.34 -> example.com", res.PeerNames[0])
	}
}

func synthDHCPDiscoverPacket(t *testing.T, clientMAC net.HardwareAddr, hostname string) []byte {
	t.Helper()

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	eth := &layers.Ethernet{SrcMAC: clientMAC, DstMAC: broadcastMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IPv4zero, DstIP: net.IPv4bcast,
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(dhcpClientPort), DstPort: layers.UDPPort(dhcpServerPort)}
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0xdeadbeef,
		ClientHWAddr: clientMAC,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
			layers.NewDHCPOption(layers.DHCPOptHostname, []byte(hostname)),
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dhcp); err != nil {
		t.Fatalf("serialize test DHCP packet: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

func TestDecodeExtractsDHCPHostname(t *testing.T) {
	_, lan, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(lan)

	clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")
	data := synthDHCPDiscoverPacket(t, clientMAC, "my-laptop")

	res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})
	if res.HasFlow {
		t.Error("expected no flow event for a broadcast DHCP DISCOVER")
	}
	if !res.HasDHCP {
		t.Fatal("expected a DHCP hostname event")
	}
	if res.DHCP.Hostname != "my-laptop" {
		t.Errorf("hostname = %q, want %q", res.DHCP.Hostname, "my-laptop")
	}
	if res.DHCP.MAC != clientMAC.String() {
		t.Errorf("mac = %q, want %q", res.DHCP.MAC, clientMAC.String())
	}
}

func TestDecodeClassifiesWANToLAN(t *testing.T) {
	_, lan, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(lan)

	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	data := synthTCPPacket(t, srcMAC, dstMAC,
		net.ParseIP("93.184.216.34"), net.ParseIP("192.168.1.50"),
		443, 54321, []byte("world"))

	res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})
	if !res.HasFlow {
		t.Fatal("expected decode to succeed")
	}
	evt := res.Flow
	if evt.Key.LocalIP != "192.168.1.50" {
		t.Errorf("local ip = %s, want 192.168.1.50", evt.Key.LocalIP)
	}
	if evt.IsLocalSrc {
		t.Error("expected IsLocalSrc = false")
	}
	if evt.LocalMAC != dstMAC.String() {
		t.Errorf("local MAC = %q, want %q", evt.LocalMAC, dstMAC.String())
	}
}

// LAN-to-LAN traffic never crosses the WAN link, so it isn't recorded.
func TestDecodeIgnoresLANToLANTraffic(t *testing.T) {
	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	d := NewDecoder(lan)

	a, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	b, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	data := synthTCPPacket(t, a, b, net.ParseIP("192.168.1.60"), net.ParseIP("192.168.1.50"), 51000, 22, nil)

	if res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)}); res.HasFlow {
		t.Errorf("expected no flow for LAN-to-LAN traffic, got %+v", res.Flow)
	}
}

// Found by the live smoke test: mDNS announcements to 224.0.0.251 were
// recorded as internet traffic.
func TestDecodeIgnoresMulticastAndLinkLocal(t *testing.T) {
	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	d := NewDecoder(lan)

	a, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	b, _ := net.ParseMAC("01:00:5e:00:00:fb")
	for _, c := range []struct{ name, src, dst string }{
		{"mDNS", "192.168.1.60", "224.0.0.251"},
		{"SSDP", "192.168.1.60", "239.255.255.250"},
		{"link-local peer", "192.168.1.60", "169.254.10.20"},
		{"from link-local", "169.254.10.20", "192.168.1.60"},
	} {
		data := synthTCPPacket(t, a, b, net.ParseIP(c.src), net.ParseIP(c.dst), 5353, 5353, nil)
		if res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)}); res.HasFlow {
			t.Errorf("%s: expected no flow, got %+v", c.name, res.Flow)
		}
	}
}

func synthVLANTCPPacket(t *testing.T, vlanID uint16, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeDot1Q}
	dot1q := &layers.Dot1Q{VLANIdentifier: vlanID, Type: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), Seq: 1, SYN: true, Window: 1024}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, eth, dot1q, ip, tcp); err != nil {
		t.Fatalf("serialize VLAN test packet: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// TestDecodeHandlesVLANTaggedTraffic reproduces the real-world failure this
// was built to fix: a mirrored trunk port carrying 802.1Q-tagged traffic
// (multiple VLANs) produced zero flows, because the hand-built BPF filter's
// fixed byte offsets assumed untagged frames, and the decoder never
// registered a Dot1Q layer to unwrap the tag even if a packet got through.
func TestDecodeHandlesVLANTaggedTraffic(t *testing.T) {
	_, lan, err := net.ParseCIDR("192.168.0.0/16") // covers multiple VLAN subnets, as in the real report
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(lan)

	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	// VLAN 10 traffic, e.g. from a mirrored trunk uplink.
	data := synthVLANTCPPacket(t, 10, srcMAC, dstMAC,
		net.ParseIP("192.168.10.100"), net.ParseIP("93.184.216.34"), 54321, 443)

	res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})
	if !res.HasFlow {
		t.Fatal("expected a flow event for VLAN-tagged IPv4 traffic")
	}
	if res.Flow.Key.LocalIP != "192.168.10.100" {
		t.Errorf("local ip = %s, want 192.168.10.100", res.Flow.Key.LocalIP)
	}
	if res.Flow.Key.RemoteIP != "93.184.216.34" {
		t.Errorf("remote ip = %s, want 93.184.216.34", res.Flow.Key.RemoteIP)
	}
	if !res.Flow.IsLocalSrc {
		t.Error("expected the LAN host to be the sender")
	}
	if res.Flow.LocalMAC != srcMAC.String() {
		t.Errorf("local MAC = %q, want %q", res.Flow.LocalMAC, srcMAC.String())
	}
}
