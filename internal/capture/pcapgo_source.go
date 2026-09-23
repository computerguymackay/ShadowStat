package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/bpf"
)

// ifiPromisc is Linux's IFF_PROMISC flag bit (see if.h), as reported in
// /sys/class/net/<iface>/flags.
const ifiPromisc = 0x100

// isPromiscuous reports whether ifaceName already has promiscuous mode
// enabled (by anyone — another capture tool, a systemd unit, a manual `ip
// link set promisc on`), so NewPcapgoSource can skip the privileged
// PACKET_ADD_MEMBERSHIP call when it's already redundant. Read-only and
// requires no special privilege itself.
func isPromiscuous(ifaceName string) (bool, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/flags", ifaceName))
	if err != nil {
		return false, err
	}
	flags, err := strconv.ParseUint(strings.TrimSpace(string(raw))[2:], 16, 32) // trim leading "0x"
	if err != nil {
		return false, fmt.Errorf("parse interface flags %q: %w", raw, err)
	}
	return flags&ifiPromisc != 0, nil
}

// packetBufSize is how many packets can queue between the kernel read loop and
// the decode goroutine before new packets are dropped rather than blocking the
// read loop.
const packetBufSize = 4096

// PcapgoSource captures packets from a Linux AF_PACKET socket via gopacket's
// pcapgo package — pure Go, no libpcap.so, no cgo.
type PcapgoSource struct {
	handle  *pcapgo.EthernetHandle
	dropped uint64
}

// NewPcapgoSource opens ifaceName in promiscuous mode and applies filter.
func NewPcapgoSource(ifaceName string, filter []bpf.RawInstruction) (*PcapgoSource, error) {
	handle, err := pcapgo.NewEthernetHandle(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("open interface %s: %w", ifaceName, err)
	}

	// Skip the privileged call entirely if something else (another capture
	// tool, a systemd unit, a manual `ip link set promisc on`) already has
	// the interface in promiscuous mode — one less use of CAP_NET_ADMIN than
	// strictly necessary. If the check itself fails for any reason, fall back
	// to just setting it unconditionally rather than blocking startup on a
	// read-only sysfs probe that isn't essential.
	already, checkErr := isPromiscuous(ifaceName)
	if checkErr != nil || !already {
		if err := handle.SetPromiscuous(true); err != nil {
			handle.Close()
			return nil, fmt.Errorf("set promiscuous mode on %s: %w", ifaceName, err)
		}
	}
	if len(filter) > 0 {
		if err := handle.SetBPF(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("set BPF filter on %s: %w", ifaceName, err)
		}
	}
	return &PcapgoSource{handle: handle}, nil
}

// Packets implements Source.
func (s *PcapgoSource) Packets(ctx context.Context) (<-chan RawPacket, <-chan error) {
	packets := make(chan RawPacket, packetBufSize)
	errs := make(chan error, 1)

	go func() {
		defer close(packets)
		defer close(errs)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			data, ci, err := s.handle.ZeroCopyReadPacketData()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				select {
				case errs <- err:
				default:
				}
				continue
			}

			// Copy out of the zero-copy buffer before handing off, since it's
			// only valid until the next read.
			cp := make([]byte, len(data))
			copy(cp, data)

			pkt := RawPacket{Data: cp, Timestamp: ci.Timestamp}
			if pkt.Timestamp.IsZero() {
				pkt.Timestamp = time.Now()
			}

			select {
			case packets <- pkt:
			default:
				s.dropped++ // queue full: drop rather than block the read loop
			}
		}
	}()

	return packets, errs
}

// Dropped returns the count of packets dropped due to a full internal queue.
func (s *PcapgoSource) Dropped() uint64 { return s.dropped }

// Close releases the underlying AF_PACKET handle.
func (s *PcapgoSource) Close() error {
	if s.handle == nil {
		return errors.New("capture: handle already closed")
	}
	s.handle.Close()
	s.handle = nil
	return nil
}
