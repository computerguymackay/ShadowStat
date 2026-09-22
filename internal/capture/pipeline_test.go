package capture

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"ShadowStat/internal/store"
)

// buildTestPcap writes a couple of synthetic packets (one LAN->WAN, one
// WAN->LAN) into an in-memory pcap buffer, standing in for a file captured
// off a real mirrored switch port per the MVP verification plan.
func buildTestPcap(t *testing.T) *bytes.Buffer {
	t.Helper()
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")

	outbound := synthTCPPacket(t, srcMAC, dstMAC,
		net.ParseIP("192.168.1.50"), net.ParseIP("93.184.216.34"), 54321, 443, []byte("hello"))
	inbound := synthTCPPacket(t, dstMAC, srcMAC,
		net.ParseIP("93.184.216.34"), net.ParseIP("192.168.1.50"), 443, 54321, []byte("world!!"))

	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	now := time.Unix(1000, 0)
	for _, pkt := range [][]byte{outbound, inbound} {
		ci := gopacket.CaptureInfo{Timestamp: now, CaptureLength: len(pkt), Length: len(pkt)}
		if err := w.WritePacket(ci, pkt); err != nil {
			t.Fatalf("write pcap packet: %v", err)
		}
	}
	return &buf
}

func TestPipelineReplayEndToEnd(t *testing.T) {
	pcapBuf := buildTestPcap(t)

	dbPath := filepath.Join(t.TempDir(), "shadowstat.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer db.Close()

	src, err := NewReplaySource(pcapBuf)
	if err != nil {
		t.Fatalf("open replay source: %v", err)
	}

	_, lan, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := NewPipeline(db, src, lan, 20*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := pipeline.Run(ctx); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	host, err := db.UpsertHost("192.168.1.50", 1000) // idempotent lookup; returns existing row
	if err != nil {
		t.Fatal(err)
	}

	flows, err := db.HostFlows(host, 0, 2000, 10)
	if err != nil {
		t.Fatal(err)
	}
	// Outbound and inbound packets carry the same 5-tuple but different
	// direction (LAN->WAN vs WAN->LAN), which is part of the flow key, so they
	// land as two separate flows_recent rows by design.
	if len(flows) != 2 {
		t.Fatalf("expected 2 direction-separated flows, got %d: %+v", len(flows), flows)
	}

	var sawOutbound, sawInbound bool
	for _, f := range flows {
		if f.RemoteIP != "93.184.216.34" || f.RemotePort != 443 {
			t.Errorf("unexpected remote peer: %s:%d", f.RemoteIP, f.RemotePort)
		}
		switch f.Direction {
		case 0:
			sawOutbound = true
			if f.BytesSent == 0 || f.BytesRecv != 0 {
				t.Errorf("outbound row: sent=%d recv=%d, want sent>0 recv=0", f.BytesSent, f.BytesRecv)
			}
		case 1:
			sawInbound = true
			if f.BytesRecv == 0 || f.BytesSent != 0 {
				t.Errorf("inbound row: sent=%d recv=%d, want sent=0 recv>0", f.BytesSent, f.BytesRecv)
			}
		}
	}
	if !sawOutbound || !sawInbound {
		t.Errorf("expected both directions present, outbound=%v inbound=%v", sawOutbound, sawInbound)
	}
}

// TestPipelineLearnsDeviceNameEndToEnd replays a DHCP DISCOVER (announcing a
// hostname) followed by ordinary LAN->WAN traffic from the same MAC/IP, and
// checks that the host ends up with both its MAC and DHCP-learned display
// name recorded — exercising the full decode -> pipeline -> store path, not
// just the individual pieces.
func TestPipelineLearnsDeviceNameEndToEnd(t *testing.T) {
	clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")
	remoteMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:04")

	dhcpPkt := synthDHCPDiscoverPacket(t, clientMAC, "my-laptop")
	flowPkt := synthTCPPacket(t, clientMAC, remoteMAC,
		net.ParseIP("192.168.1.60"), net.ParseIP("93.184.216.34"), 55000, 443, []byte("hi"))

	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	now := time.Unix(1000, 0)
	for _, pkt := range [][]byte{dhcpPkt, flowPkt} {
		ci := gopacket.CaptureInfo{Timestamp: now, CaptureLength: len(pkt), Length: len(pkt)}
		if err := w.WritePacket(ci, pkt); err != nil {
			t.Fatalf("write pcap packet: %v", err)
		}
	}

	dbPath := filepath.Join(t.TempDir(), "shadowstat.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer db.Close()

	src, err := NewReplaySource(&buf)
	if err != nil {
		t.Fatalf("open replay source: %v", err)
	}
	_, lan, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := NewPipeline(db, src, lan, 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := pipeline.Run(ctx); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	hosts, err := db.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	var found *store.Host
	for i := range hosts {
		if hosts[i].IP == "192.168.1.60" {
			found = &hosts[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a host for 192.168.1.60, got %+v", hosts)
	}
	if !found.MACAddress.Valid || found.MACAddress.String != clientMAC.String() {
		t.Errorf("mac_address = %+v, want %q", found.MACAddress, clientMAC.String())
	}
	if !found.DisplayName.Valid || found.DisplayName.String != "my-laptop" {
		t.Errorf("display_name = %+v, want %q", found.DisplayName, "my-laptop")
	}
}
