package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

// synthEthIPPacket builds a minimal Ethernet+IPv4 frame (no L4 payload),
// optionally wrapped in a single 802.1Q VLAN tag, for exercising the BPF
// filter directly, independent of any capture socket.
func synthEthIPPacket(t *testing.T, etherType layers.EthernetType, vlanID uint16, srcIP, dstIP net.IP) []byte {
	t.Helper()
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}

	layersToSerialize := []gopacket.SerializableLayer{}
	if vlanID != 0 {
		layersToSerialize = append(layersToSerialize,
			&layers.Ethernet{SrcMAC: mac, DstMAC: mac, EthernetType: layers.EthernetTypeDot1Q},
			&layers.Dot1Q{VLANIdentifier: vlanID, Type: etherType},
		)
	} else {
		layersToSerialize = append(layersToSerialize, &layers.Ethernet{SrcMAC: mac, DstMAC: mac, EthernetType: etherType})
	}

	if etherType == layers.EthernetTypeIPv4 {
		layersToSerialize = append(layersToSerialize,
			&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP})
	} else {
		layersToSerialize = append(layersToSerialize, gopacket.Payload([]byte{0, 0, 0, 0}))
	}

	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		t.Fatalf("serialize test frame: %v", err)
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

func TestCompileIPv4Filter(t *testing.T) {
	filter, err := CompileIPv4Filter()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		pkt    []byte
		accept bool
	}{
		{
			name:   "untagged IPv4",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeIPv4, 0, net.ParseIP("192.168.1.50"), net.ParseIP("93.184.216.34")),
			accept: true,
		},
		{
			name:   "untagged IPv4, broadcast destination (DHCP)",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeIPv4, 0, net.IPv4zero, net.IPv4bcast),
			accept: true,
		},
		{
			name:   "untagged IPv4, address unrelated to any configured subnet",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeIPv4, 0, net.ParseIP("10.0.0.5"), net.ParseIP("93.184.216.34")),
			accept: true, // BPF no longer filters by address — Decoder does, see decode_test.go
		},
		{
			name:   "untagged non-IPv4 (ARP)",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeARP, 0, nil, nil),
			accept: false,
		},
		{
			name:   "VLAN-tagged IPv4 (802.1Q trunk, e.g. a mirrored trunk port)",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeIPv4, 10, net.ParseIP("192.168.10.50"), net.ParseIP("93.184.216.34")),
			accept: true,
		},
		{
			name:   "VLAN-tagged non-IPv4 (ARP inside the tag)",
			pkt:    synthEthIPPacket(t, layers.EthernetTypeARP, 10, nil, nil),
			accept: false,
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
