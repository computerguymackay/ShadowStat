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

	evt, ok := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})
	if !ok {
		t.Fatal("expected decode to succeed")
	}

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

	evt, ok := d.Decode(RawPacket{Data: data, Timestamp: time.Unix(1000, 0)})
	if !ok {
		t.Fatal("expected decode to succeed")
	}
	if evt.Key.Direction != 1 {
		t.Errorf("direction = %d, want 1 (WAN->LAN)", evt.Key.Direction)
	}
	if evt.Key.LocalIP != "192.168.1.50" {
		t.Errorf("local ip = %s, want 192.168.1.50", evt.Key.LocalIP)
	}
	if evt.IsLocalSrc {
		t.Error("expected IsLocalSrc = false")
	}
}
