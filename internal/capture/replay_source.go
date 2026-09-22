package capture

import (
	"context"
	"io"

	"github.com/google/gopacket/pcapgo"
)

// ReplaySource reads packets from a .pcap file and feeds them into the exact
// same RawPacket channel the live AF_PACKET source uses, so a captured-in-advance
// file can exercise the real decode/aggregate/flush pipeline without needing a
// mirrored switch port. Intended for tests and offline verification, not
// production use (see the MVP verification plan).
type ReplaySource struct {
	r *pcapgo.Reader
}

// NewReplaySource wraps an already-open pcap file reader.
func NewReplaySource(r io.Reader) (*ReplaySource, error) {
	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, err
	}
	return &ReplaySource{r: pr}, nil
}

// Packets implements Source, reading every packet in the file and then closing
// the channels (there's no live socket to keep open).
func (s *ReplaySource) Packets(ctx context.Context) (<-chan RawPacket, <-chan error) {
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

			data, ci, err := s.r.ReadPacketData()
			if err == io.EOF {
				return
			}
			if err != nil {
				select {
				case errs <- err:
				default:
				}
				return
			}

			select {
			case packets <- RawPacket{Data: data, Timestamp: ci.Timestamp}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return packets, errs
}

// Close is a no-op; the underlying io.Reader's lifecycle is owned by the caller.
func (s *ReplaySource) Close() error { return nil }
