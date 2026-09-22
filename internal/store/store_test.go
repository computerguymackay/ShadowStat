package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "shadowstat.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSettingsRoundTrip(t *testing.T) {
	db := openTestDB(t)

	if _, ok, err := db.GetSetting("nope"); err != nil || ok {
		t.Fatalf("expected missing setting, got ok=%v err=%v", ok, err)
	}

	if err := db.SetSetting(KeyLANSubnetCIDR, "192.168.1.0/24"); err != nil {
		t.Fatal(err)
	}
	v, ok, err := db.GetSetting(KeyLANSubnetCIDR)
	if err != nil || !ok || v != "192.168.1.0/24" {
		t.Fatalf("got v=%q ok=%v err=%v", v, ok, err)
	}

	if err := db.SetSettings(map[string]string{KeyRetentionDays: "30", KeyCaptureInterface: "eth0"}); err != nil {
		t.Fatal(err)
	}
	all, err := db.AllSettings()
	if err != nil {
		t.Fatal(err)
	}
	if all[KeyRetentionDays] != "30" || all[KeyCaptureInterface] != "eth0" {
		t.Fatalf("unexpected settings: %+v", all)
	}
}

func TestUpsertHostBumpsLastSeen(t *testing.T) {
	db := openTestDB(t)

	id1, err := db.UpsertHost("192.168.1.50", 1000)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := db.UpsertHost("192.168.1.50", 2000)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("expected same host id, got %d and %d", id1, id2)
	}

	host, err := db.HostByID(id1)
	if err != nil {
		t.Fatal(err)
	}
	if host.LastSeen != 2000 {
		t.Errorf("last_seen = %d, want 2000", host.LastSeen)
	}
	if host.FirstSeen != 1000 {
		t.Errorf("first_seen = %d, want 1000", host.FirstSeen)
	}
}

func TestFlowInsertRollupAndSeriesRoundTrip(t *testing.T) {
	db := openTestDB(t)

	hostID, err := db.UpsertHost("192.168.1.50", 60)
	if err != nil {
		t.Fatal(err)
	}

	records := []FlowRecord{
		{
			HostID: hostID, Direction: DirLANToWAN, Proto: 6,
			LocalIP: "192.168.1.50", LocalPort: 1234,
			RemoteIP: "1.2.3.4", RemotePort: 443,
			FirstSeen: 30, LastSeen: 45,
			BytesSent: 1000, BytesRecv: 200, PacketsSent: 5, PacketsRecv: 2,
		},
		{
			HostID: hostID, Direction: DirLANToWAN, Proto: 6,
			LocalIP: "192.168.1.50", LocalPort: 1235,
			RemoteIP: "5.6.7.8", RemotePort: 443,
			FirstSeen: 50, LastSeen: 55,
			BytesSent: 500, BytesRecv: 100, PacketsSent: 3, PacketsRecv: 1,
		},
	}
	if err := db.InsertFlows(records); err != nil {
		t.Fatal(err)
	}

	// Both flows fall in the [0,60) minute bucket.
	if err := db.RollupFromFlowsRecent(0, 60); err != nil {
		t.Fatal(err)
	}

	points, err := db.HostSeriesFromRollup("1m", hostID, 0, 60, -1)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(points))
	}
	if points[0].BytesSent != 1500 || points[0].BytesRecv != 300 {
		t.Errorf("bucket totals = sent=%d recv=%d, want sent=1500 recv=300", points[0].BytesSent, points[0].BytesRecv)
	}

	flows, err := db.HostFlows(hostID, 0, 60, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("expected 2 flow detail rows, got %d", len(flows))
	}
}

func TestUserAndSessionLifecycle(t *testing.T) {
	db := openTestDB(t)

	if exists, err := db.AnyUserExists(); err != nil || exists {
		t.Fatalf("expected no users yet, got exists=%v err=%v", exists, err)
	}

	id, err := db.CreateUser("admin", "hashed", 1000)
	if err != nil {
		t.Fatal(err)
	}

	u, err := db.UserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != id || u.PasswordHash != "hashed" {
		t.Fatalf("unexpected user: %+v", u)
	}

	if err := db.CreateSession("tok123", id, 1000, 2000); err != nil {
		t.Fatal(err)
	}
	sess, err := db.SessionByToken("tok123")
	if err != nil {
		t.Fatal(err)
	}
	if sess.UserID != id {
		t.Fatalf("session user id = %d, want %d", sess.UserID, id)
	}
	if sess.ElevatedUntil.Valid {
		t.Error("expected session to start unelevated")
	}

	if err := db.ElevateSession("tok123", 5000); err != nil {
		t.Fatal(err)
	}
	sess, err = db.SessionByToken("tok123")
	if err != nil {
		t.Fatal(err)
	}
	if !sess.ElevatedUntil.Valid || sess.ElevatedUntil.Int64 != 5000 {
		t.Errorf("expected elevated_until=5000, got %+v", sess.ElevatedUntil)
	}

	if err := db.DeleteSession("tok123"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SessionByToken("tok123"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeviceNaming(t *testing.T) {
	db := openTestDB(t)

	hostID, err := db.UpsertHost("192.168.1.50", 1000)
	if err != nil {
		t.Fatal(err)
	}

	// No MAC/hostname yet.
	host, err := db.HostByID(hostID)
	if err != nil {
		t.Fatal(err)
	}
	if host.MACAddress.Valid || host.DisplayName.Valid {
		t.Fatalf("expected no MAC/display name yet, got %+v", host)
	}

	const mac = "aa:bb:cc:dd:ee:01"
	if err := db.SetHostMAC(hostID, mac); err != nil {
		t.Fatal(err)
	}

	if err := db.UpsertDHCPHostname(mac, "my-laptop", 2000); err != nil {
		t.Fatal(err)
	}

	host, err = db.HostByID(hostID)
	if err != nil {
		t.Fatal(err)
	}
	if !host.MACAddress.Valid || host.MACAddress.String != mac {
		t.Errorf("mac_address = %+v, want %q", host.MACAddress, mac)
	}
	if !host.DisplayName.Valid || host.DisplayName.String != "my-laptop" {
		t.Errorf("display_name = %+v, want %q", host.DisplayName, "my-laptop")
	}

	hostname, ok, err := db.HostnameByMAC(mac)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || hostname != "my-laptop" {
		t.Errorf("HostnameByMAC = (%q, %v), want (\"my-laptop\", true)", hostname, ok)
	}

	// A DHCP hostname learned for a MAC not yet attached to any host shouldn't error.
	if err := db.UpsertDHCPHostname("11:22:33:44:55:66", "unknown-device", 3000); err != nil {
		t.Fatal(err)
	}
}

func TestUpsertHostBumpsLastSeenAcrossRepeatedCalls(t *testing.T) {
	db := openTestDB(t)

	id1, err := db.UpsertHost("192.168.1.50", 1000)
	if err != nil {
		t.Fatal(err)
	}
	// Simulates what the capture pipeline now does on every flush, not just
	// the first time an IP is seen — this used to silently no-op because the
	// pipeline cached the id and never called UpsertHost again.
	id2, err := db.UpsertHost("192.168.1.50", 5000)
	if err != nil {
		t.Fatal(err)
	}
	id3, err := db.UpsertHost("192.168.1.50", 3000) // out-of-order/older timestamp
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 || id2 != id3 {
		t.Fatalf("expected stable host id across calls, got %d, %d, %d", id1, id2, id3)
	}

	host, err := db.HostByID(id1)
	if err != nil {
		t.Fatal(err)
	}
	if host.LastSeen != 5000 {
		t.Errorf("last_seen = %d, want 5000 (the max seenAt across all calls)", host.LastSeen)
	}
}

// TestMigrationAddsMACColumn simulates a database created before the
// mac_address column existed, and checks that Open() migrates it in place
// without erroring or losing existing data.
func TestMigrationAddsMACColumn(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "shadowstat.db")

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
		CREATE TABLE schema_meta (version INTEGER NOT NULL);
		INSERT INTO schema_meta (version) VALUES (1);
		CREATE TABLE hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL UNIQUE,
			display_name TEXT,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL
		);
		INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('192.168.1.50', 100, 200);
	`)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() on pre-migration database failed: %v", err)
	}
	defer db.Close()

	hosts, err := db.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].IP != "192.168.1.50" {
		t.Fatalf("expected pre-existing host to survive migration, got %+v", hosts)
	}

	if err := db.SetHostMAC(hosts[0].ID, "aa:bb:cc:dd:ee:01"); err != nil {
		t.Fatalf("SetHostMAC after migration: %v", err)
	}
}
