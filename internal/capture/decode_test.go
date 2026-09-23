package capture

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"ShadowStat/internal/store"
)

func synthTCPPacket(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
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
		SYN:     true,
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
	if res.HasDNS {
		t.Error("expected no DNS event for a plain TCP packet")
	}

	evt := res.Flow
	if evt.Key.Direction != 0 {
		t.Errorf("direction = %d, want 0 (LAN->WAN)", evt.Key.Direction)
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

func synthDNSQueryPacket(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, qname string) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(51000), DstPort: layers.UDPPort(dnsServicePort)}
	dns := &layers.DNS{
		ID:      1234,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte(qname), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		t.Fatalf("serialize test DNS packet: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

func TestDecodeExtractsDNSQuery(t *testing.T) {
	_, lan, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(lan)

	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	data := synthDNSQueryPacket(t, srcMAC, dstMAC,
		net.ParseIP("192.168.1.50"), net.ParseIP("8.8.8.8"), "example.com")

	res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})
	if !res.HasFlow {
		t.Fatal("expected flow decode to succeed")
	}
	if res.Flow.Key.RemotePort != dnsServicePort {
		t.Errorf("remote port = %d, want %d", res.Flow.Key.RemotePort, dnsServicePort)
	}
	if !res.HasDNS {
		t.Fatal("expected a DNS query event")
	}
	if res.DNS.QName != "example.com" {
		t.Errorf("qname = %q, want %q", res.DNS.QName, "example.com")
	}
	if res.DNS.LocalIP != "192.168.1.50" {
		t.Errorf("local ip = %q, want %q", res.DNS.LocalIP, "192.168.1.50")
	}
	if res.DNS.QType != uint16(layers.DNSTypeA) {
		t.Errorf("qtype = %d, want %d", res.DNS.QType, layers.DNSTypeA)
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
	if evt.Key.Direction != 1 {
		t.Errorf("direction = %d, want 1 (WAN->LAN)", evt.Key.Direction)
	}
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

func TestDecodeLANToLANProducesBothPerspectives(t *testing.T) {
	_, lan, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(lan)

	scannerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	targetMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	// A LAN device (scanner) probing another LAN device (target) — both
	// addresses are within the configured subnet.
	data := synthTCPPacket(t, scannerMAC, targetMAC,
		net.ParseIP("192.168.1.60"), net.ParseIP("192.168.1.50"),
		51000, 22, []byte(""))

	res := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})
	if !res.HasFlow || !res.HasFlow2 {
		t.Fatalf("expected both flow perspectives, got HasFlow=%v HasFlow2=%v", res.HasFlow, res.HasFlow2)
	}

	initiator := res.Flow
	if initiator.Key.Direction != store.DirLANOut {
		t.Errorf("initiator direction = %d, want %d (DirLANOut)", initiator.Key.Direction, store.DirLANOut)
	}
	if initiator.Key.LocalIP != "192.168.1.60" || initiator.Key.RemoteIP != "192.168.1.50" {
		t.Errorf("initiator local/remote = %s/%s, want 192.168.1.60/192.168.1.50", initiator.Key.LocalIP, initiator.Key.RemoteIP)
	}
	if !initiator.IsLocalSrc {
		t.Error("expected initiator IsLocalSrc = true")
	}
	if initiator.LocalMAC != scannerMAC.String() {
		t.Errorf("initiator MAC = %q, want %q", initiator.LocalMAC, scannerMAC.String())
	}

	target := res.Flow2
	if target.Key.Direction != store.DirLANIn {
		t.Errorf("target direction = %d, want %d (DirLANIn)", target.Key.Direction, store.DirLANIn)
	}
	if target.Key.LocalIP != "192.168.1.50" || target.Key.RemoteIP != "192.168.1.60" {
		t.Errorf("target local/remote = %s/%s, want 192.168.1.50/192.168.1.60", target.Key.LocalIP, target.Key.RemoteIP)
	}
	if target.Key.LocalPort != 22 {
		t.Errorf("target local port = %d, want 22 (the probed port)", target.Key.LocalPort)
	}
	if target.IsLocalSrc {
		t.Error("expected target IsLocalSrc = false")
	}
	if target.LocalMAC != targetMAC.String() {
		t.Errorf("target MAC = %q, want %q", target.LocalMAC, targetMAC.String())
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
	if res.Flow.Key.Direction != store.DirLANToWAN {
		t.Errorf("direction = %d, want %d (DirLANToWAN)", res.Flow.Key.Direction, store.DirLANToWAN)
	}
	if res.Flow.LocalMAC != srcMAC.String() {
		t.Errorf("local MAC = %q, want %q", res.Flow.LocalMAC, srcMAC.String())
	}
}
