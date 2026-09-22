package detect

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ShadowStat/internal/store"
)

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "shadowstat.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ageHost backdates a host's first_seen so it's outside the new-destination
// detector's learning period, without needing to wait real time in a test.
func ageHost(t *testing.T, db *store.DB, hostID int64, age time.Duration) {
	t.Helper()
	_, err := db.Writer.Exec("UPDATE hosts SET first_seen = ? WHERE id = ?",
		time.Now().Add(-age).Unix(), hostID)
	if err != nil {
		t.Fatal(err)
	}
}

func insertFlow(t *testing.T, db *store.DB, hostID int64, remoteIP string, remotePort int, at int64) {
	t.Helper()
	err := db.InsertFlows([]store.FlowRecord{{
		HostID: hostID, Direction: store.DirLANToWAN, Proto: 6,
		LocalIP: "192.168.1.50", LocalPort: 5000,
		RemoteIP: remoteIP, RemotePort: remotePort,
		FirstSeen: at, LastSeen: at,
		BytesSent: 100, BytesRecv: 100, PacketsSent: 1, PacketsRecv: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewDestinationsAlertsOnUnseenPeer(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.50", now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	ageHost(t, db, hostID, 10*24*time.Hour) // past the learning period

	insertFlow(t, db, hostID, "1.2.3.4", 443, now.Unix())

	NewDestinations(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].Kind != store.AlertKindNewDestination {
		t.Errorf("kind = %q, want %q", alerts[0].Kind, store.AlertKindNewDestination)
	}

	// Running again immediately shouldn't duplicate the alert (same peer,
	// still within the known_peers/cooldown window).
	insertFlow(t, db, hostID, "1.2.3.4", 443, now.Unix())
	NewDestinations(db, now)
	alerts, err = db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected still 1 alert after re-run, got %d", len(alerts))
	}
}

func TestNewDestinationsSuppressedDuringLearningPeriod(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.51", now.Unix()) // brand new host
	if err != nil {
		t.Fatal(err)
	}
	insertFlow(t, db, hostID, "5.6.7.8", 443, now.Unix())

	NewDestinations(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts during learning period, got %d: %+v", len(alerts), alerts)
	}
}

func TestBeaconingDetectsRegularIntervals(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.50", now.Unix())
	if err != nil {
		t.Fatal(err)
	}

	// 6 flows to the same peer, exactly 60s apart — textbook beacon.
	base := now.Add(-6 * time.Minute).Unix()
	for i := 0; i < 6; i++ {
		insertFlow(t, db, hostID, "9.9.9.9", 443, base+int64(i)*60)
	}

	Beaconing(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Kind != store.AlertKindBeaconing {
		t.Fatalf("expected 1 beaconing alert, got %+v", alerts)
	}
}

func TestBeaconingIgnoresIrregularIntervals(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.50", now.Unix())
	if err != nil {
		t.Fatal(err)
	}

	// Wildly irregular intervals — should not be flagged.
	base := now.Add(-6 * time.Hour).Unix()
	offsets := []int64{0, 30, 5000, 5200, 20000, 20100}
	for _, off := range offsets {
		insertFlow(t, db, hostID, "9.9.9.9", 443, base+off)
	}

	Beaconing(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no beaconing alert for irregular intervals, got %+v", alerts)
	}
}

func TestExfilRatioFlagsHighUploadNoDownload(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.50", now.Unix())
	if err != nil {
		t.Fatal(err)
	}

	err = db.InsertFlows([]store.FlowRecord{{
		HostID: hostID, Direction: store.DirLANToWAN, Proto: 6,
		LocalIP: "192.168.1.50", LocalPort: 5000,
		RemoteIP: "1.2.3.4", RemotePort: 443,
		FirstSeen: now.Unix(), LastSeen: now.Unix(),
		BytesSent: 100 * 1024 * 1024, BytesRecv: 1024, PacketsSent: 1000, PacketsRecv: 2,
	}})
	if err != nil {
		t.Fatal(err)
	}

	ExfilRatio(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Kind != store.AlertKindExfilRatio {
		t.Fatalf("expected 1 exfil_ratio alert, got %+v", alerts)
	}
}

func TestExfilRatioIgnoresNormalTraffic(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.50", now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	err = db.InsertFlows([]store.FlowRecord{{
		HostID: hostID, Direction: store.DirLANToWAN, Proto: 6,
		LocalIP: "192.168.1.50", LocalPort: 5000,
		RemoteIP: "1.2.3.4", RemotePort: 443,
		FirstSeen: now.Unix(), LastSeen: now.Unix(),
		BytesSent: 10 * 1024, BytesRecv: 5 * 1024 * 1024, PacketsSent: 20, PacketsRecv: 4000,
	}})
	if err != nil {
		t.Fatal(err)
	}

	ExfilRatio(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no exfil alert for download-heavy traffic, got %+v", alerts)
	}
}

func TestPortScanFlagsManyPortsOnOneTarget(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.50", now.Unix())
	if err != nil {
		t.Fatal(err)
	}

	var records []store.FlowRecord
	for i := 0; i < 40; i++ {
		records = append(records, store.FlowRecord{
			HostID: hostID, Direction: store.DirLANToWAN, Proto: 6,
			LocalIP: "192.168.1.50", LocalPort: 5000,
			RemoteIP: "10.0.0.1", RemotePort: 1000 + i,
			FirstSeen: now.Unix(), LastSeen: now.Unix(),
			BytesSent: 40, BytesRecv: 0, PacketsSent: 1, PacketsRecv: 0,
		})
	}
	if err := db.InsertFlows(records); err != nil {
		t.Fatal(err)
	}

	PortScan(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Kind != store.AlertKindPortScan {
		t.Fatalf("expected 1 port_scan alert, got %+v", alerts)
	}
	if !strings.Contains(alerts[0].Detail, `"remote_ip":"10.0.0.1"`) {
		t.Errorf("expected detail to name the single target, got %q", alerts[0].Detail)
	}
	if !strings.Contains(alerts[0].Detail, `"port_count":40`) {
		t.Errorf("expected detail to include the port count, got %q", alerts[0].Detail)
	}
}

func TestPortScanIgnoresManyHostsOnSamePort(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.50", now.Unix())
	if err != nil {
		t.Fatal(err)
	}

	// Classic normal-browsing shape: many different remote hosts, all on 443
	// — this used to trip the old "distinct (ip,port) pairs" detector even
	// though it's not scan-like at all (each target only sees one port).
	var records []store.FlowRecord
	for i := 0; i < 40; i++ {
		records = append(records, store.FlowRecord{
			HostID: hostID, Direction: store.DirLANToWAN, Proto: 6,
			LocalIP: "192.168.1.50", LocalPort: 5000,
			RemoteIP: fmt.Sprintf("10.0.%d.1", i), RemotePort: 443,
			FirstSeen: now.Unix(), LastSeen: now.Unix(),
			BytesSent: 1000, BytesRecv: 5000, PacketsSent: 5, PacketsRecv: 10,
		})
	}
	if err := db.InsertFlows(records); err != nil {
		t.Fatal(err)
	}

	PortScan(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no port_scan alert for many-hosts-one-port traffic, got %+v", alerts)
	}
}

func TestDNSAnomalyFlagsVolumeAndEntropy(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	hostID, err := db.UpsertHost("192.168.1.50", now.Unix())
	if err != nil {
		t.Fatal(err)
	}

	var records []store.DNSQueryRecord
	for i := 0; i < dnsVolumeThreshold+10; i++ {
		records = append(records, store.DNSQueryRecord{
			HostID: hostID, QName: "example.com", QType: 1, TS: now.Unix(),
		})
	}
	// A long, high-entropy (effectively random) label typical of a DGA domain.
	records = append(records, store.DNSQueryRecord{
		HostID: hostID, QName: "qz8x2kd9f7m3vw6ntlr4y.net", QType: 1, TS: now.Unix(),
	})
	if err := db.InsertDNSQueries(records); err != nil {
		t.Fatal(err)
	}

	DNSAnomaly(db, now)

	alerts, err := db.ListAlertsForHost(hostID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("expected 2 dns_anomaly alerts (volume + entropy), got %d: %+v", len(alerts), alerts)
	}
	for _, a := range alerts {
		if a.Kind != store.AlertKindDNSAnomaly {
			t.Errorf("unexpected alert kind %q", a.Kind)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy("aaaaaaaa"); e != 0 {
		t.Errorf("entropy of repeated char = %v, want 0", e)
	}
	if e := shannonEntropy("qz8x2kd9f7m3vw6ntlr4y"); e < dnsEntropyThreshold {
		t.Errorf("entropy of random-looking string = %v, want >= %v", e, dnsEntropyThreshold)
	}
}
