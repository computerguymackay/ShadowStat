package store

import (
	"testing"
	"time"
)

func queryInt(t *testing.T, db *DB, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Reader.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func flow(hostID int64, dir int, remote string, port int, lastSeen, sent, recv int64) FlowRecord {
	return FlowRecord{
		HostID: hostID, Direction: dir, Proto: 6,
		LocalIP: "192.168.1.50", LocalPort: 50000, RemoteIP: remote, RemotePort: port,
		FirstSeen: lastSeen - 5, LastSeen: lastSeen,
		BytesSent: sent, BytesRecv: recv, PacketsSent: 1, PacketsRecv: 1,
		ServicePort: port, AppProto: "HTTPS", AppConfidence: ConfPayload,
	}
}

func TestRunRollupCountsEachRowExactlyOnce(t *testing.T) {
	db := openTestDB(t)
	hostID, _ := db.UpsertHost("192.168.1.50", 100)

	if err := db.InsertFlows([]FlowRecord{
		flow(hostID, DirOutbound, "1.1.1.1", 443, 100, 1000, 5000),
		flow(hostID, DirOutbound, "1.1.1.1", 443, 110, 200, 800),
		flow(hostID, DirInbound, "2.2.2.2", 22, 4000, 300, 30),
	}); err != nil {
		t.Fatal(err)
	}

	n, err := db.RunRollup()
	if err != nil || n != 3 {
		t.Fatalf("first rollup processed %d rows (err %v), want 3", n, err)
	}
	// A second run must not add anything again.
	if n, err := db.RunRollup(); err != nil || n != 0 {
		t.Fatalf("second rollup processed %d rows (err %v), want 0", n, err)
	}

	for _, table := range []string{"rollup_1m", "rollup_5m", "rollup_1h", "rollup_1d"} {
		if got := queryInt(t, db, "SELECT SUM(bytes_sent) FROM "+table); got != 1500 {
			t.Errorf("%s sent = %d, want 1500", table, got)
		}
	}
	tot, ok, err := db.HostTotalsByID(hostID)
	if err != nil || !ok {
		t.Fatalf("host totals: ok=%v err=%v", ok, err)
	}
	if tot.BytesSent != 1500 || tot.BytesRecv != 5830 {
		t.Errorf("totals = %d/%d, want 1500/5830", tot.BytesSent, tot.BytesRecv)
	}
	if tot.TotalsSince != 95 {
		t.Errorf("totals_since = %d, want 95 (earliest first_seen)", tot.TotalsSince)
	}
	if tot.ExactSince.Valid {
		t.Error("exact_since should be NULL for a host first counted after the upgrade")
	}
	if got := queryInt(t, db, "SELECT bytes_recv FROM host_peer_daily WHERE remote_ip = '1.1.1.1'"); got != 5800 {
		t.Errorf("host_peer_daily recv for 1.1.1.1 = %d, want 5800", got)
	}
}

// A flush can land after the minute it belongs to was already rolled up.
// The v1 job lost such rows; the watermark job must still count them.
func TestRunRollupCountsLateRowsInAnAlreadyRolledMinute(t *testing.T) {
	db := openTestDB(t)
	hostID, _ := db.UpsertHost("192.168.1.50", 100)

	if err := db.InsertFlows([]FlowRecord{flow(hostID, DirOutbound, "1.1.1.1", 443, 120, 100, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}
	// Late row for the same minute bucket (120..179).
	if err := db.InsertFlows([]FlowRecord{flow(hostID, DirOutbound, "1.1.1.1", 443, 130, 50, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT bytes_sent FROM rollup_1m WHERE bucket_ts = 120"); got != 150 {
		t.Errorf("minute bucket = %d, want 150", got)
	}
}

// After downtime, one run must fill every tier, including the daily one
// (v1 only filled rollup_1d after 24h of continuous uptime).
func TestRunRollupCatchesUpEveryTierAfterAGap(t *testing.T) {
	db := openTestDB(t)
	hostID, _ := db.UpsertHost("192.168.1.50", 0)

	var rows []FlowRecord
	for h := int64(0); h < 30; h++ {
		rows = append(rows, flow(hostID, DirOutbound, "1.1.1.1", 443, h*3600+10, 10, 0))
	}
	if err := db.InsertFlows(rows); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM rollup_1h"); got != 30 {
		t.Errorf("rollup_1h buckets = %d, want 30", got)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM rollup_1d"); got != 2 {
		t.Errorf("rollup_1d buckets = %d, want 2", got)
	}
	if got := queryInt(t, db, "SELECT SUM(bytes_sent) FROM rollup_1d"); got != 300 {
		t.Errorf("rollup_1d sent = %d, want 300", got)
	}
}

func TestRunRollupIgnoresLegacyLANRows(t *testing.T) {
	db := openTestDB(t)
	hostID, _ := db.UpsertHost("192.168.1.50", 100)
	lan := flow(hostID, 2, "192.168.1.60", 22, 100, 999, 0) // v1 LAN-to-LAN direction
	if err := db.InsertFlows([]FlowRecord{lan, flow(hostID, DirOutbound, "1.1.1.1", 443, 100, 1, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT bytes_sent FROM host_totals"); got != 1 {
		t.Errorf("host_totals sent = %d, want 1 (LAN row excluded)", got)
	}
}

func TestPruneNeverDeletesRowsTheRollupHasNotSeen(t *testing.T) {
	db := openTestDB(t)
	hostID, _ := db.UpsertHost("192.168.1.50", 100)
	if err := db.InsertFlows([]FlowRecord{flow(hostID, DirOutbound, "1.1.1.1", 443, 100, 1, 0)}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(10*86400, 0)
	if err := db.Prune(now, RetentionFor(30)); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM flows_recent"); got != 1 {
		t.Fatalf("unrolled row was pruned")
	}
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}
	if err := db.Prune(now, RetentionFor(30)); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM flows_recent"); got != 0 {
		t.Errorf("rolled-up old row was not pruned")
	}
	if got := queryInt(t, db, "SELECT bytes_sent FROM host_totals"); got != 1 {
		t.Errorf("host_totals lost data on prune: %d", got)
	}
}

func TestChooseSeriesTier(t *testing.T) {
	const now = int64(1_000_000_000)
	const day = int64(86400)
	cases := []struct {
		name     string
		from, to int64
		want     string
	}{
		{"last 24h", now - day, now, "raw"},
		{"last 7 days", now - 7*day, now, "1m"},
		// v1 served 7–10 day ranges from rollup_1m, which only keeps 7 days.
		{"last 9 days", now - 9*day, now, "5m"},
		{"last 30 days", now - 30*day, now, "5m"},
		{"last 90 days", now - 90*day, now, "1h"},
		{"3 years", now - 3*365*day, now, "1d"},
		{"one hour, 20 days ago", now - 20*day, now - 20*day + 3600, "5m"},
	}
	for _, c := range cases {
		if got := ChooseSeriesTier(c.from, c.to, now, 30); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRetentionKeepsCoarseTiersAtLeastAsLongAsFine(t *testing.T) {
	for _, days := range []int{7, 30, 90, 365, 1000} {
		r := RetentionFor(days)
		if !(r.Rollup1m <= r.Rollup5m && r.Rollup5m <= r.Rollup1h && r.Rollup1h <= r.Rollup1d) {
			t.Errorf("retention_days=%d: tiers not monotonic: %+v", days, r)
		}
	}
}

func TestHostBreakdownRecentAndDaily(t *testing.T) {
	db := openTestDB(t)
	hostID, _ := db.UpsertHost("192.168.1.50", 100)

	rows := []FlowRecord{
		flow(hostID, DirOutbound, "1.1.1.1", 443, 100, 100, 9000),
		flow(hostID, DirOutbound, "1.1.1.1", 443, 200, 50, 1000),
		flow(hostID, DirInbound, "2.2.2.2", 22, 300, 10, 20),
		flow(hostID, DirUnknown, "3.3.3.3", 51820, 300, 1, 1),
	}
	rows[3].AppProto, rows[3].AppConfidence, rows[3].Proto = "", ConfUnknown, 17
	if err := db.InsertFlows(rows); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertPeerNames([]PeerName{{IP: "1.1.1.1", Name: "one.one.one.one", LastSeen: 90}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}

	for _, recentCutoff := range []int64{0, 1_000_000} { // flows_recent path, then host_peer_daily path
		b, err := db.HostBreakdown(hostID, 0, 1000, recentCutoff, 10)
		if err != nil {
			t.Fatal(err)
		}
		if b.DayResolution != (recentCutoff > 0) {
			t.Errorf("cutoff %d: day_resolution = %v", recentCutoff, b.DayResolution)
		}
		if len(b.Peers) != 3 {
			t.Fatalf("cutoff %d: peers = %+v", recentCutoff, b.Peers)
		}
		top := b.Peers[0]
		if top.RemoteIP != "1.1.1.1" || top.Name != "one.one.one.one" || top.BytesSent != 150 || top.BytesRecv != 10000 {
			t.Errorf("cutoff %d: top peer = %+v", recentCutoff, top)
		}
		if top.StartedBy != "host" || len(top.Ports) != 1 || top.Ports[0] != 443 {
			t.Errorf("cutoff %d: top peer started_by/ports = %q/%v", recentCutoff, top.StartedBy, top.Ports)
		}
		if b.Peers[1].StartedBy != "remote" {
			t.Errorf("cutoff %d: ssh peer started_by = %q, want remote", recentCutoff, b.Peers[1].StartedBy)
		}
		if len(b.Services) != 3 || b.Services[0].AppProto != "HTTPS" || b.Services[0].AppConfidence != ConfPayload || b.Services[0].Peers != 1 {
			t.Errorf("cutoff %d: services = %+v", recentCutoff, b.Services)
		}
	}
}
