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

	id, err := db.CreateUser("admin", "hashed", RoleAdmin, 1000)
	if err != nil {
		t.Fatal(err)
	}

	u, err := db.UserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != id || u.PasswordHash != "hashed" || u.Role != RoleAdmin {
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

// TestMigrationDefaultsExistingUserToAdmin simulates a database created
// before the users.role column existed (i.e. every ShadowStat install prior
// to multi-user support) and checks the pre-existing account survives as an
// admin — not demoted to standard, which would lock the original owner out
// of settings/user management on upgrade.
func TestMigrationDefaultsExistingUserToAdmin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "shadowstat.db")

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
		CREATE TABLE schema_meta (version INTEGER NOT NULL);
		INSERT INTO schema_meta (version) VALUES (1);
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			must_reauth_at INTEGER
		);
		INSERT INTO users (username, password_hash, created_at) VALUES ('admin', 'hashed', 1000);
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

	u, err := db.UserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != RoleAdmin {
		t.Errorf("role = %q, want %q (pre-existing account should default to admin)", u.Role, RoleAdmin)
	}
}

func TestUserRoleManagement(t *testing.T) {
	db := openTestDB(t)

	adminID, err := db.CreateUser("admin", "hash1", RoleAdmin, 1000)
	if err != nil {
		t.Fatal(err)
	}
	standardID, err := db.CreateUser("viewer", "hash2", RoleStandard, 2000)
	if err != nil {
		t.Fatal(err)
	}

	users, err := db.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0].Username != "admin" || users[1].Username != "viewer" {
		t.Errorf("expected users ordered oldest-first, got %+v", users)
	}

	count, err := db.CountAdmins()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("CountAdmins = %d, want 1", count)
	}

	if err := db.UpdateUserRole(standardID, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	count, err = db.CountAdmins()
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("CountAdmins after promotion = %d, want 2", count)
	}

	if err := db.DeleteUser(adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UserByID(adminID); err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
	users, err = db.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user remaining, got %d", len(users))
	}
}

func TestDetectorEnabledDefaultsAndOverride(t *testing.T) {
	db := openTestDB(t)

	if !db.DetectorEnabled(KeyDetectorPortScan) {
		t.Error("expected detector to default to enabled when unset")
	}

	if err := db.SetSetting(KeyDetectorPortScan, "0"); err != nil {
		t.Fatal(err)
	}
	if db.DetectorEnabled(KeyDetectorPortScan) {
		t.Error("expected detector to be disabled after setting 0")
	}

	if err := db.SetSetting(KeyDetectorPortScan, "1"); err != nil {
		t.Fatal(err)
	}
	if !db.DetectorEnabled(KeyDetectorPortScan) {
		t.Error("expected detector to be enabled after setting 1")
	}
}

func TestAcknowledgeAllAlerts(t *testing.T) {
	db := openTestDB(t)

	hostID, err := db.UpsertHost("192.168.1.50", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := db.InsertAlert(AlertRecord{
			HostID: hostID, Kind: AlertKindNewDestination, Severity: SeverityInfo,
			Summary: "test", DedupeKey: string(rune('a' + i)), DetectedAt: 1000,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.InsertAlert(AlertRecord{
		HostID: hostID, Kind: AlertKindPortScan, Severity: SeverityCritical,
		Summary: "test", DedupeKey: "scan", DetectedAt: 1000,
	}); err != nil {
		t.Fatal(err)
	}

	// Acknowledging one kind only clears that kind.
	n, err := db.AcknowledgeAllAlerts(AlertKindNewDestination)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("acknowledged %d alerts, want 5", n)
	}

	unacked, err := db.ListAlerts(100, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(unacked) != 1 || unacked[0].Kind != AlertKindPortScan {
		t.Fatalf("expected only the port_scan alert left unacknowledged, got %+v", unacked)
	}

	// kind filter on ListAlerts narrows results regardless of ack state.
	filtered, err := db.ListAlerts(100, false, AlertKindNewDestination)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 5 {
		t.Fatalf("expected 5 new_destination alerts, got %d", len(filtered))
	}

	// Acknowledging all (no kind filter) clears the rest.
	n, err = db.AcknowledgeAllAlerts("")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("acknowledged %d alerts, want 1", n)
	}
	unacked, err = db.ListAlerts(100, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(unacked) != 0 {
		t.Fatalf("expected no unacknowledged alerts left, got %+v", unacked)
	}
}
