package capture

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// snapLen is the number of bytes the kernel is told to keep for accepted packets.
const snapLen = 262144

const (
	etherTypeOff          = 12
	etherTypeIP4          = 0x0800
	etherTypeVLAN         = 0x8100 // 802.1Q; the tag itself is 4 bytes, shifting everything after it
	vlanInnerEtherTypeOff = 16     // offset of the real EtherType inside a single 802.1Q tag
)

// CompileIPv4Filter builds a raw BPF program that accepts any IPv4 Ethernet
// frame — untagged, or carrying a single 802.1Q VLAN tag — and rejects
// everything else. Built by hand (via golang.org/x/net/bpf) rather than a
// filter-string compiler, since we deliberately avoid any libpcap dependency.
//
// This deliberately does NOT filter by LAN-subnet address at the BPF level
// (an earlier version did): a mirrored trunk port carrying multiple VLANs
// means "does this address fall in the configured subnet" isn't answerable
// from a fixed byte offset alone once tagging is involved, and getting that
// address-matching logic right by hand in raw BPF twice already produced
// real bugs (broadcast destinations, then VLAN tags shifting every
// downstream offset). Address/subnet filtering is instead done in Go
// (Decoder, using net.IPNet.Contains) once the packet is already fully
// parsed — simpler, less error-prone, and cheap enough at the traffic
// volumes this is built for. This BPF program's only job is cutting non-IP
// noise (ARP, STP, IPv6 for now, etc.) before it reaches userspace at all.
//
// Known MVP limitations: IPv4 only (IPv6 isn't decoded yet), and only a
// single 802.1Q tag (QinQ/double-tagging isn't matched).
func CompileIPv4Filter() ([]bpf.RawInstruction, error) {
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: etherTypeOff, Size: 2},                        // 0: outer ethertype
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIP4, SkipTrue: 4},     // 1: untagged IPv4 -> accept (idx 6)
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherTypeVLAN, SkipTrue: 2}, // 2: not tagged either -> reject (idx 5)
		bpf.LoadAbsolute{Off: vlanInnerEtherTypeOff, Size: 2},               // 3: inner ethertype (past the 4-byte tag)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIP4, SkipTrue: 1},     // 4: tagged IPv4 -> accept (idx 6)
		bpf.RetConstant{Val: 0},                                             // 5: reject
		bpf.RetConstant{Val: snapLen},                                       // 6: accept
	}

	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("assemble BPF program: %w", err)
	}
	return raw, nil
}
