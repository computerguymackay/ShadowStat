package capture

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/net/bpf"
)

// snapLen is the number of bytes the kernel is told to keep for accepted packets.
const snapLen = 262144

// CompileLANFilter builds a raw BPF program that accepts IPv4 Ethernet frames
// where either the source or destination address falls within lanCIDR, and
// rejects everything else. Built by hand (via golang.org/x/net/bpf) rather than
// a filter-string compiler, since we deliberately avoid any libpcap dependency.
//
// Known MVP limitation: IPv4 only. IPv6 LAN subnets are not yet supported by
// this filter (tracked as future work alongside the rest of the detection roadmap).
func CompileLANFilter(lanCIDR string) ([]bpf.RawInstruction, error) {
	_, ipnet, err := net.ParseCIDR(lanCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse LAN subnet: %w", err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("LAN subnet must be IPv4: %s", lanCIDR)
	}
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	network := binary.BigEndian.Uint32(ip4) & mask

	// Ethernet header: 14 bytes. IPv4 header: src at offset 26, dst at offset 30.
	const (
		etherTypeOff = 12
		srcIPOff     = 26
		dstIPOff     = 30
		etherTypeIP4 = 0x0800
	)

	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: etherTypeOff, Size: 2},                       // 0
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherTypeIP4, SkipTrue: 6}, // 1: not IPv4 -> reject (idx 8)
		bpf.LoadAbsolute{Off: srcIPOff, Size: 4},                           // 2
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask},                     // 3
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: network, SkipTrue: 4},         // 4: src matches -> accept (idx 9)
		bpf.LoadAbsolute{Off: dstIPOff, Size: 4},                           // 5
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask},                     // 6
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: network, SkipTrue: 1},         // 7: dst matches -> accept (idx 9)
		bpf.RetConstant{Val: 0},                                            // 8: reject
		bpf.RetConstant{Val: snapLen},                                      // 9: accept
	}

	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("assemble BPF program: %w", err)
	}
	return raw, nil
}
