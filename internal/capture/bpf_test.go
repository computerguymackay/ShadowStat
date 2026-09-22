package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

// synthEthIPPacket builds a minimal Ethernet+IPv4 frame (no L4 payload) for
// exercising the BPF filter directly, independent of any capture socket.
func synthEthIPPacket(t *testing.T, etherType layers.EthernetType, srcIP, dstIP net.IP) []byte {
	t.Helper()
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")

	eth := &layers.Ethernet{SrcMAC: mac, DstMAC: mac, EthernetType: etherType}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}

	if etherType != layers.EthernetTypeIPv4 {
		if err := gopacket.SerializeLayers(buf, opts, eth, gopacket.Payload([]byte{0, 0, 0, 0})); err != nil {
			t.Fatalf("serialize non-IPv4 frame: %v", err)
		}
		out := make([]byte, len(buf.Bytes()))
		copy(out, buf.Bytes())
		return out
	}

	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip); err != nil {
		t.Fatalf("serialize IPv4 frame: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// runBPF assembles and disassembles filter (the same round trip SetBPF's
// caller and the kernel perform) and runs it in x/net/bpf's pure-Go VM,
// returning whether the packet was accepted.
func runBPF(t *testing.T, filter []bpf.RawInstruction, pkt []byte) bool {
	t.Helper()
	insts, ok := bpf.Disassemble(filter)
	if !ok {
		t.Fatal("failed to disassemble filter program")
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("build BPF VM: %v", err)
	}
	n, err := vm.Run(pkt)
	if err != nil {
		t.Fatalf("run BPF VM: %v", err)
	}
	return n > 0
}

func TestCompileLANFilter(t *testing.T) {
	filter, err := CompileLANFilter("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		pkt    []byte
		accept bool
	}{
		{
			name:   "src in LAN subnet",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeIPv4, net.ParseIP("192.168.1.50"), net.ParseIP("93.184.216.34")),
			accept: true,
		},
		{
			name:   "dst in LAN subnet",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeIPv4, net.ParseIP("93.184.216.34"), net.ParseIP("192.168.1.50")),
			accept: true,
		},
		{
			name:   "neither side in LAN subnet",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeIPv4, net.ParseIP("10.0.0.5"), net.ParseIP("93.184.216.34")),
			accept: false,
		},
		{
			name:   "non-IPv4 ethertype",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeARP, nil, nil),
			accept: false,
		},
		{
			name:   "broadcast destination (DHCP)",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeIPv4, net.IPv4zero, net.IPv4bcast),
			accept: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runBPF(t, filter, tc.pkt)
			if got != tc.accept {
				t.Errorf("accept = %v, want %v", got, tc.accept)
			}
		})
	}
}
