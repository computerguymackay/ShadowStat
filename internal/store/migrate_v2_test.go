package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// buildV1Database creates a database exactly as the last v1 release left
// it — its real schema.sql (saved in testdata) plus representative data in
// every tier — and returns its path.
//
// Rollup coverage in the fixture: rollup_1h ends at 3600, rollup_5m at 3900,
// rollup_1m at 3960. Rows in a finer tier that fall inside a coarser tier's
// coverage are deliberately given huge values, so double counting shows up.
func buildV1Database(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shadowstat.db")
	schema, err := os.ReadFile("testdata/schema_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(string(schema)); err != nil {
		t.Fatalf("apply v1 schema: %v", err)
	}
	if _, err := raw.Exec(`
		INSERT INTO schema_meta (version) VALUES (1);
		INSERT INTO hosts (id, ip, first_seen, last_seen) VALUES (1, '192.168.1.50', 0, 4000), (2, '192.168.1.51', 3990, 4000);

		-- v1 recorded each packet direction as its own row: 0 = from the LAN, 1 = to the LAN.
		INSERT INTO flows_recent (host_id, direction, proto, local_ip, local_port, remote_ip, remote_port,
		                          first_seen, last_seen, bytes_sent, bytes_recv, packets_sent, packets_recv) VALUES
		    (1, 0, 6, '192.168.1.50', 50000, '93.184.216.34', 443, 3995, 4000, 100, 0, 1, 0),
		    (1, 1, 6, '192.168.1.50', 50000, '93.184.216.34', 443, 3995, 4000, 0, 1000, 0, 2),
		    (1, 0, 6, '192.168.1.50', 50001, '93.184.216.34', 443, 3690, 3700, 55555, 0, 1, 0), -- covered by rollup_1m
		    (1, 2, 6, '192.168.1.50', 51000, '192.168.1.60', 22, 3995, 4000, 999, 0, 1, 0),     -- LAN-to-LAN
		    (2, 1, 17, '192.168.1.51', 123, '162.159.200.1', 40000, 3990, 4000, 0, 10, 0, 1);

		INSERT INTO rollup_1h (host_id, direction, bucket_ts, bytes_sent, bytes_recv) VALUES
		    (1, 0, 0, 5000, 0), (1, 1, 0, 0, 7000), (1, 2, 0, 12345, 0);
		INSERT INTO rollup_5m (host_id, direction, bucket_ts, bytes_sent, bytes_recv) VALUES
		    (1, 0, 0, 999999, 0),   -- covered by rollup_1h
		    (1, 0, 3600, 300, 0);
		INSERT INTO rollup_1m (host_id, direction, bucket_ts, bytes_sent, bytes_recv) VALUES
		    (1, 0, 3600, 777, 0),   -- covered by rollup_5m
		    (1, 1, 3900, 0, 40);

		INSERT INTO alerts (host_id, kind, severity, summary, dedupe_key, detected_at)
		    VALUES (1, 'port_scan', 'critical', 'old alert', 'k', 1000);
	`); err != nil {
		t.Fatalf("seed v1 data: %v", err)
	}
	return path
}

func TestMigrationV1ToV2(t *testing.T) {
	path := buildV1Database(t)

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open() on v1 database: %v", err)
	}

	if v := queryInt(t, db, "SELECT version FROM schema_meta"); v != 2 {
		t.Errorf("schema version = %d, want 2", v)
	}

	// v1 packet-direction rows become "unknown", with a guessed service port.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM flows_recent WHERE direction IN (0, 1)"); n != 0 {
		t.Errorf("%d v1 rows still carry a packet direction", n)
	}
	if p := queryInt(t, db, "SELECT service_port FROM flows_recent WHERE remote_port = 443 LIMIT 1"); p != 443 {
		t.Errorf("service_port = %d, want 443", p)
	}
	if p := queryInt(t, db, "SELECT service_port FROM flows_recent WHERE host_id = 2"); p != 123 {
		t.Errorf("service_port for NTP row = %d, want 123", p)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM flows_recent WHERE direction = 2"); n != 1 {
		t.Errorf("legacy LAN row should be left untouched, found %d", n)
	}

	// host_totals: each tier used only where the coarser ones don't reach.
	h1, ok, err := db.HostTotalsByID(1)
	if err != nil || !ok {
		t.Fatalf("host 1 totals: ok=%v err=%v", ok, err)
	}
	if h1.BytesSent != 5000+300+100 || h1.BytesRecv != 7000+40+1000 {
		t.Errorf("host 1 totals = %d/%d, want 5400/8040", h1.BytesSent, h1.BytesRecv)
	}
	if h1.TotalsSince != 0 || !h1.ExactSince.Valid {
		t.Errorf("host 1 totals_since=%d exact_since=%+v, want 0 and set", h1.TotalsSince, h1.ExactSince)
	}
	h2, _, _ := db.HostTotalsByID(2)
	if h2.BytesRecv != 10 || h2.TotalsSince != 3990 {
		t.Errorf("host 2 totals = %+v", h2)
	}

	// host_peer_daily is seeded from every WAN row left in flows_recent.
	if s := queryInt(t, db, "SELECT SUM(bytes_sent) FROM host_peer_daily WHERE host_id = 1"); s != 55555+100 {
		t.Errorf("host_peer_daily sent = %d, want %d", s, 55555+100)
	}

	// The watermark covers every pre-existing row, so the next rollup is a no-op.
	if n, err := db.RunRollup(); err != nil || n != 0 {
		t.Errorf("first rollup after migration processed %d rows (err %v), want 0", n, err)
	}

	// Old tables are left in place for rollback.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM alerts"); n != 1 {
		t.Errorf("alerts table should be untouched, has %d rows", n)
	}

	// New rows use the new columns and are counted exactly once on top.
	rec := flow(1, DirOutbound, "93.184.216.34", 443, 5000, 1, 2)
	if err := db.InsertFlows([]FlowRecord{rec}); err != nil {
		t.Fatalf("insert v2 flow into migrated db: %v", err)
	}
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}
	after, _, _ := db.HostTotalsByID(1)
	if after.BytesSent != h1.BytesSent+1 || after.BytesRecv != h1.BytesRecv+2 {
		t.Errorf("totals after new flow = %d/%d, want +1/+2 on %d/%d", after.BytesSent, after.BytesRecv, h1.BytesSent, h1.BytesRecv)
	}
	db.Close()

	// Reopening must not migrate again.
	db, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()
	again, _, _ := db.HostTotalsByID(1)
	if again != after {
		t.Errorf("reopen changed totals: %+v -> %+v", after, again)
	}
}

func TestFreshDatabaseStartsAtV2(t *testing.T) {
	db := openTestDB(t)
	if v := queryInt(t, db, "SELECT version FROM schema_meta"); v != 2 {
		t.Errorf("schema version = %d, want 2", v)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM host_totals"); n != 0 {
		t.Errorf("fresh db has %d host_totals rows", n)
	}
}

// Rolling back (schema_meta reset to 1, as the README describes), letting
// the v1 binary write a little, then upgrading again must not double count.
func TestMigrationAfterRollbackDoesNotDoubleCount(t *testing.T) {
	path := buildV1Database(t)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := db.HostTotalsByID(1)

	// What the v1 binary does while rolled back: insert with its own column
	// list (new columns take their defaults) and roll up into rollup_1m.
	if _, err := db.Writer.Exec(`
		UPDATE schema_meta SET version = 1;
		INSERT INTO flows_recent (host_id, direction, proto, local_ip, local_port, remote_ip, remote_port,
		                          first_seen, last_seen, bytes_sent, bytes_recv, packets_sent, packets_recv)
		VALUES (1, 0, 6, '192.168.1.50', 50002, '93.184.216.34', 443, 4990, 5000, 7, 0, 1, 0);
		INSERT INTO rollup_1m (host_id, direction, bucket_ts, bytes_sent) VALUES (1, 0, 4980, 7);`); err != nil {
		t.Fatalf("simulate v1 writes: %v", err)
	}
	db.Close()

	db, err = Open(path)
	if err != nil {
		t.Fatalf("re-upgrade: %v", err)
	}
	defer db.Close()
	after, _, _ := db.HostTotalsByID(1)
	// The 7 bytes written while rolled back are counted once. The fixture's
	// two newest flows (sent 100, received 1000) were never rolled up by the
	// v1 job, and the rollup_1m row the v1 binary later wrote moves the
	// coverage boundary past them, so a re-upgrade can't recover them: a
	// small, bounded loss right at the original upgrade point, never a
	// double count.
	wantSent, wantRecv := before.BytesSent+7-100, before.BytesRecv-1000
	if after.BytesSent != wantSent || after.BytesRecv != wantRecv {
		t.Errorf("totals after rollback + re-upgrade = %d/%d, want %d/%d",
			after.BytesSent, after.BytesRecv, wantSent, wantRecv)
	}
	if n, err := db.RunRollup(); err != nil || n != 0 {
		t.Errorf("rollup after re-upgrade processed %d rows (err %v), want 0", n, err)
	}
}
