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

var (
	lanMAC, _    = net.ParseMAC("aa:bb:cc:dd:ee:01")
	routerMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:02")
	hostIP       = net.ParseIP("192.168.1.50")
)

func writePcap(t *testing.T, pkts [][]byte) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	now := time.Unix(1000, 0)
	for _, pkt := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: now, CaptureLength: len(pkt), Length: len(pkt)}
		if err := w.WritePacket(ci, pkt); err != nil {
			t.Fatalf("write pcap packet: %v", err)
		}
	}
	return &buf
}

func openPipelineDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "shadowstat.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func runPipeline(t *testing.T, db *store.DB, src Source, runFor time.Duration) {
	t.Helper()
	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	pipeline := NewPipeline(db, src, lan, 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), runFor)
	defer cancel()
	if err := pipeline.Run(ctx); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}
}

func replay(t *testing.T, db *store.DB, pkts [][]byte) {
	t.Helper()
	src, err := NewReplaySource(writePcap(t, pkts))
	if err != nil {
		t.Fatalf("open replay source: %v", err)
	}
	runPipeline(t, db, src, 150*time.Millisecond)
}

func synthUDPPacket(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize UDP packet: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func synthPing(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, icmpType uint8) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: srcIP, DstIP: dstIP}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(icmpType, 0), Id: 1, Seq: 1}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, ip, icmp); err != nil {
		t.Fatalf("serialize ICMP packet: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// out/in build packets from and to the LAN host, to keep the scenario readable.
func out(t *testing.T, remote string, lport, rport uint16, syn, ack bool, payload []byte) []byte {
	return synthTCPFlags(t, lanMAC, routerMAC, hostIP, net.ParseIP(remote), lport, rport, syn, ack, payload)
}

func in(t *testing.T, remote string, rport, lport uint16, syn, ack bool, payload []byte) []byte {
	return synthTCPFlags(t, routerMAC, lanMAC, net.ParseIP(remote), hostIP, rport, lport, syn, ack, payload)
}

// TestPipelineReplayEndToEnd replays a small but realistic capture — DNS,
// an HTTPS connection, QUIC, an inbound SSH session, a ping, unidentifiable
// UDP, and LAN-to-LAN noise — through the real decode -> aggregate -> flush
// -> rollup path, and checks every one of the five things ShadowStat is for:
// who talked to what, ports, protocols, bytes each way, and the totals.
func TestPipelineReplayEndToEnd(t *testing.T) {
	const (
		web   = "93.184.216.34"
		quic  = "142.250.1.1"
		admin = "203.0.113.9"
		odd   = "198.51.100.7"
		ping  = "8.8.8.8"
	)
	pkts := [][]byte{
		// The router (the LAN's resolver) answers a lookup for the web server.
		synthDNSAnswerPacket(t, net.ParseIP("192.168.1.1"), hostIP, "example.com", net.ParseIP(web)),

		// Outbound HTTPS: handshake, ClientHello, server data.
		out(t, web, 50000, 443, true, false, nil),
		in(t, web, 443, 50000, true, true, nil),
		out(t, web, 50000, 443, false, true, tlsClientHello),
		in(t, web, 443, 50000, false, true, tlsAppData),

		// Outbound QUIC.
		synthUDPPacket(t, lanMAC, routerMAC, hostIP, net.ParseIP(quic), 50001, 443, quicInitial),
		synthUDPPacket(t, routerMAC, lanMAC, net.ParseIP(quic), hostIP, 443, 50001, quicShort),

		// Inbound SSH to a port-forwarded server on the LAN host.
		in(t, admin, 40000, 22, true, false, nil),
		out(t, admin, 22, 40000, true, true, nil),
		out(t, admin, 22, 40000, false, true, []byte("SSH-2.0-OpenSSH_9.6\r\n")),
		in(t, admin, 40000, 22, false, true, []byte("SSH-2.0-PuTTY\r\n")),

		// A ping and its reply.
		synthPing(t, lanMAC, routerMAC, hostIP, net.ParseIP(ping), layers.ICMPv4TypeEchoRequest),
		synthPing(t, routerMAC, lanMAC, net.ParseIP(ping), hostIP, layers.ICMPv4TypeEchoReply),

		// Something nobody could identify.
		synthUDPPacket(t, lanMAC, routerMAC, hostIP, net.ParseIP(odd), 40000, 50000, []byte{0xde, 0xad}),
		synthUDPPacket(t, routerMAC, lanMAC, net.ParseIP(odd), hostIP, 50000, 40000, []byte{0xbe, 0xef}),

		// LAN-to-LAN: not WAN traffic, must not be recorded.
		synthTCPPacket(t, lanMAC, routerMAC, hostIP, net.ParseIP("192.168.1.60"), 51000, 445, nil),
	}
	var wantSent, wantRecv int64
	for _, p := range pkts[1 : len(pkts)-1] {
		res := NewDecoder(&net.IPNet{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(24, 32)}).Decode(RawPacket{Data: p})
		if res.Flow.IsLocalSrc {
			wantSent += int64(len(p))
		} else {
			wantRecv += int64(len(p))
		}
	}

	db := openPipelineDB(t)
	replay(t, db, pkts)
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}

	hosts, err := db.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].IP != hostIP.String() {
		t.Fatalf("hosts = %+v, want only %s (LAN-to-LAN and DNS traffic must not create hosts)", hosts, hostIP)
	}
	hostID := hosts[0].ID

	convs, err := db.HostConversations(hostID, 0, 2000, 100)
	if err != nil {
		t.Fatal(err)
	}
	byPeer := map[string]store.Conversation{}
	for _, c := range convs {
		byPeer[c.RemoteIP] = c
	}
	if len(convs) != 5 {
		t.Fatalf("conversations = %+v, want one per conversation (5)", convs)
	}

	want := []struct {
		peer          string
		direction     int
		servicePort   int
		app           string
		appConfidence int
	}{
		{web, store.DirOutbound, 443, "HTTPS", store.ConfPayload},
		{quic, store.DirOutbound, 443, "QUIC", store.ConfPayload},
		{admin, store.DirInbound, 22, "SSH", store.ConfPayload},
		{ping, store.DirOutbound, 0, "", store.ConfUnknown},
		{odd, store.DirUnknown, 40000, "", store.ConfUnknown},
	}
	for _, w := range want {
		c, ok := byPeer[w.peer]
		if !ok {
			t.Errorf("no conversation with %s", w.peer)
			continue
		}
		if c.Direction != w.direction || c.ServicePort != w.servicePort || c.AppProto != w.app || c.AppConfidence != w.appConfidence {
			t.Errorf("%s: direction=%d service=%d app=%q/%d, want %d %d %q/%d",
				w.peer, c.Direction, c.ServicePort, c.AppProto, c.AppConfidence,
				w.direction, w.servicePort, w.app, w.appConfidence)
		}
		// Each conversation is one row carrying both directions' bytes.
		if c.BytesSent == 0 || c.BytesRecv == 0 {
			t.Errorf("%s: sent=%d recv=%d, want both non-zero", w.peer, c.BytesSent, c.BytesRecv)
		}
	}

	totals, ok, err := db.HostTotalsByID(hostID)
	if err != nil || !ok {
		t.Fatalf("host totals: ok=%v err=%v", ok, err)
	}
	if totals.BytesSent != wantSent || totals.BytesRecv != wantRecv {
		t.Errorf("totals = %d/%d, want %d/%d", totals.BytesSent, totals.BytesRecv, wantSent, wantRecv)
	}

	b, err := db.HostBreakdown(hostID, 0, 2000, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var named bool
	for _, p := range b.Peers {
		if p.RemoteIP == web && p.Name == "example.com" {
			named = true
		}
	}
	if !named {
		t.Errorf("expected %s to be named example.com from the DNS answer, peers = %+v", web, b.Peers)
	}
}

// scriptedSource emits packet batches with a pause between them, so a test
// can make one conversation span several flush windows.
type scriptedSource struct {
	batches [][][]byte
	gap     time.Duration
}

func (s *scriptedSource) Packets(ctx context.Context) (<-chan RawPacket, <-chan error) {
	pkts := make(chan RawPacket)
	errs := make(chan error)
	go func() {
		defer close(pkts)
		defer close(errs)
		for i, batch := range s.batches {
			if i > 0 {
				time.Sleep(s.gap)
			}
			for _, p := range batch {
				pkts <- RawPacket{Data: p, Timestamp: time.Unix(1000+int64(i), 0)}
			}
		}
		<-ctx.Done()
	}()
	return pkts, errs
}

func (s *scriptedSource) Close() error { return nil }

// A long-lived connection's later flush windows see no handshake and only
// opaque payload. They must keep the direction and protocol worked out from
// the first window.
func TestPipelineKeepsLabelsAcrossFlushes(t *testing.T) {
	const web = "93.184.216.34"
	src := &scriptedSource{
		gap: 100 * time.Millisecond, // several 20ms flushes apart
		batches: [][][]byte{
			{
				out(t, web, 50000, 8443, true, false, nil),
				in(t, web, 8443, 50000, true, true, nil),
				out(t, web, 50000, 8443, false, true, tlsClientHello),
			},
			{
				// Later: no SYN, no recognizable payload.
				out(t, web, 50000, 8443, false, true, []byte{0x01, 0x02, 0x03}),
				in(t, web, 8443, 50000, false, true, []byte{0x04, 0x05, 0x06}),
			},
		},
	}

	db := openPipelineDB(t)
	runPipeline(t, db, src, 300*time.Millisecond)

	rows, err := db.Reader.Query(`SELECT direction, service_port, app_proto, app_confidence FROM flows_recent ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var dir, svc, conf int
		var app string
		if err := rows.Scan(&dir, &svc, &app, &conf); err != nil {
			t.Fatal(err)
		}
		n++
		if dir != store.DirOutbound || svc != 8443 || app != "HTTPS" || conf != store.ConfPayload {
			t.Errorf("flush row %d: direction=%d service=%d app=%q/%d, want outbound 8443 HTTPS/payload", n, dir, svc, app, conf)
		}
	}
	if n < 2 {
		t.Fatalf("expected the conversation to span at least 2 flush rows, got %d", n)
	}
}

// TestPipelineLearnsDeviceNameEndToEnd replays a DHCP DISCOVER (announcing a
// hostname) followed by ordinary LAN->WAN traffic from the same MAC/IP, and
// checks that the host ends up with both its MAC and DHCP-learned display
// name recorded.
func TestPipelineLearnsDeviceNameEndToEnd(t *testing.T) {
	clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")
	remoteMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:04")

	db := openPipelineDB(t)
	replay(t, db, [][]byte{
		synthDHCPDiscoverPacket(t, clientMAC, "my-laptop"),
		synthTCPPacket(t, clientMAC, remoteMAC, net.ParseIP("192.168.1.60"), net.ParseIP("93.184.216.34"), 55000, 443, []byte("hi")),
	})

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
