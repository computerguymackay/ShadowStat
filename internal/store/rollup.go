package store

import (
	"database/sql"
	"fmt"
	"time"
)

// watermarkKey names the rollup_state row holding the highest flows_recent.id
// already processed by RunRollup.
const watermarkKey = "flows_recent_id"

// rollupBatch caps how many flows_recent rows one RunRollup transaction
// processes, so catching up after long downtime doesn't hold the writer for
// one huge transaction. RunRollup loops until it's caught up.
const rollupBatch = 200_000

// directionClause returns a SQL fragment filtering on direction when direction
// is a valid value, or an empty string to leave rows unfiltered.
func directionClause(direction int) string {
	if direction < 0 {
		return ""
	}
	return " AND direction = ?"
}

// rollupTiers lists each rollup table with its bucket width in seconds.
var rollupTiers = []struct {
	name, table string
	width       int64
}{
	{"1m", "rollup_1m", 60},
	{"5m", "rollup_5m", 300},
	{"1h", "rollup_1h", 3600},
	{"1d", "rollup_1d", 86400},
}

// rollupTables maps a granularity name to its table name; also used to validate
// caller-supplied granularity strings before interpolating into SQL.
var rollupTables = map[string]string{
	"1m": "rollup_1m",
	"5m": "rollup_5m",
	"1h": "rollup_1h",
	"1d": "rollup_1d",
}

// Retention is how long each tier of data is kept.
type Retention struct {
	FlowsRecent time.Duration
	Rollup1m    time.Duration
	Rollup5m    time.Duration
	Rollup1h    time.Duration
	Rollup1d    time.Duration
	PeerDaily   time.Duration // host_peer_daily and peer_names
}

// RetentionFor returns the retention policy for the user's retention_days
// setting. retention_days governs the per-peer/port breakdown
// (host_peer_daily), which is the only tier that grows with the number of
// peers. The graph tiers are small and keep their fixed windows; rollup_1d
// is kept at least as long as rollup_1h so a coarser tier never expires
// before a finer one. host_totals is never pruned.
func RetentionFor(retentionDays int) Retention {
	day := 24 * time.Hour
	r := time.Duration(retentionDays) * day
	return Retention{
		FlowsRecent: day,
		Rollup1m:    7 * day,
		Rollup5m:    60 * day,
		Rollup1h:    2 * 365 * day,
		Rollup1d:    max(r, 2*365*day),
		PeerDaily:   r,
	}
}

// ChooseSeriesTier picks which data to serve a [from, to] graph from: the
// finest tier that still holds data back to `from` and keeps the point
// count reasonable. "raw" means flows_recent, bucketed per minute on the fly.
func ChooseSeriesTier(from, to, now int64, retentionDays int) string {
	ret := RetentionFor(retentionDays)
	const maxPoints = 20_000
	span := to - from
	covers := func(d time.Duration) bool { return from >= now-int64(d.Seconds()) }

	switch {
	case covers(ret.FlowsRecent) && span/60 <= maxPoints:
		return "raw"
	case covers(ret.Rollup1m) && span/60 <= maxPoints:
		return "1m"
	case covers(ret.Rollup5m) && span/300 <= maxPoints:
		return "5m"
	case covers(ret.Rollup1h) && span/3600 <= maxPoints:
		return "1h"
	default:
		return "1d"
	}
}

// RunRollup folds every flows_recent row newer than the saved watermark into
// all four rollup tiers, host_totals and host_peer_daily, then advances the
// watermark — all in one transaction per batch. Because progress is tracked
// by row id rather than by wall-clock window, each row is counted exactly
// once no matter when the job runs, how late a flush lands, or how long the
// process was down. Returns the number of rows processed.
func (db *DB) RunRollup() (int64, error) {
	var total int64
	for {
		n, err := db.rollupBatch()
		total += n
		if err != nil || n == 0 {
			return total, err
		}
	}
}

func (db *DB) rollupBatch() (int64, error) {
	tx, err := db.Writer.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	last, err := watermark(tx)
	if err != nil {
		return 0, err
	}
	var maxID int64
	if err := tx.QueryRow("SELECT COALESCE(MAX(id), 0) FROM flows_recent").Scan(&maxID); err != nil {
		return 0, err
	}
	if maxID <= last {
		return 0, nil
	}
	upTo := min(maxID, last+rollupBatch)
	newRows := "id > ? AND id <= ? AND " + wanDirections

	for _, t := range rollupTiers {
		q := fmt.Sprintf(
			`INSERT INTO %s (host_id, direction, bucket_ts, bytes_sent, bytes_recv, packets_sent, packets_recv)
			 SELECT host_id, direction, (last_seen/%d)*%d AS b,
			        SUM(bytes_sent), SUM(bytes_recv), SUM(packets_sent), SUM(packets_recv)
			 FROM flows_recent WHERE %s
			 GROUP BY host_id, direction, b
			 ON CONFLICT (host_id, direction, bucket_ts) DO UPDATE SET
			     bytes_sent = bytes_sent + excluded.bytes_sent,
			     bytes_recv = bytes_recv + excluded.bytes_recv,
			     packets_sent = packets_sent + excluded.packets_sent,
			     packets_recv = packets_recv + excluded.packets_recv`,
			t.table, t.width, t.width, newRows)
		if _, err := tx.Exec(q, last, upTo); err != nil {
			return 0, fmt.Errorf("rollup %s: %w", t.name, err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO host_totals (host_id, bytes_sent, bytes_recv, packets_sent, packets_recv, totals_since)
		 SELECT host_id, SUM(bytes_sent), SUM(bytes_recv), SUM(packets_sent), SUM(packets_recv), MIN(first_seen)
		 FROM flows_recent WHERE `+newRows+`
		 GROUP BY host_id
		 ON CONFLICT (host_id) DO UPDATE SET
		     bytes_sent = bytes_sent + excluded.bytes_sent,
		     bytes_recv = bytes_recv + excluded.bytes_recv,
		     packets_sent = packets_sent + excluded.packets_sent,
		     packets_recv = packets_recv + excluded.packets_recv,
		     totals_since = MIN(totals_since, excluded.totals_since)`,
		last, upTo); err != nil {
		return 0, fmt.Errorf("update host_totals: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT INTO host_peer_daily
		     (host_id, day, remote_ip, proto, service_port, app_proto, direction, app_confidence,
		      bytes_sent, bytes_recv, packets_sent, packets_recv)
		 SELECT host_id, (last_seen/86400)*86400 AS d, remote_ip, proto, service_port, app_proto, direction,
		        MAX(app_confidence), SUM(bytes_sent), SUM(bytes_recv), SUM(packets_sent), SUM(packets_recv)
		 FROM flows_recent WHERE `+newRows+`
		 GROUP BY host_id, d, remote_ip, proto, service_port, app_proto, direction
		 ON CONFLICT (host_id, day, remote_ip, proto, service_port, app_proto, direction) DO UPDATE SET
		     app_confidence = MAX(app_confidence, excluded.app_confidence),
		     bytes_sent = bytes_sent + excluded.bytes_sent,
		     bytes_recv = bytes_recv + excluded.bytes_recv,
		     packets_sent = packets_sent + excluded.packets_sent,
		     packets_recv = packets_recv + excluded.packets_recv`,
		last, upTo); err != nil {
		return 0, fmt.Errorf("update host_peer_daily: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT INTO rollup_state (name, value) VALUES (?, ?)
		 ON CONFLICT(name) DO UPDATE SET value = excluded.value`, watermarkKey, upTo); err != nil {
		return 0, err
	}
	return upTo - last, tx.Commit()
}

func watermark(tx *sql.Tx) (int64, error) {
	var v int64
	err := tx.QueryRow("SELECT value FROM rollup_state WHERE name = ?", watermarkKey).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return v, err
}

// Prune deletes data older than each tier's retention window, relative to now.
func (db *DB) Prune(now time.Time, ret Retention) error {
	cut := func(d time.Duration) int64 { return now.Add(-d).Unix() }

	if err := db.PruneFlowsRecent(cut(ret.FlowsRecent)); err != nil {
		return fmt.Errorf("prune flows_recent: %w", err)
	}
	for _, t := range []struct {
		table string
		keep  time.Duration
	}{
		{"rollup_1m", ret.Rollup1m},
		{"rollup_5m", ret.Rollup5m},
		{"rollup_1h", ret.Rollup1h},
		{"rollup_1d", ret.Rollup1d},
	} {
		if _, err := db.Writer.Exec(fmt.Sprintf("DELETE FROM %s WHERE bucket_ts < ?", t.table), cut(t.keep)); err != nil {
			return fmt.Errorf("prune %s: %w", t.table, err)
		}
	}
	// A day bucket is kept until its whole day has aged out.
	if _, err := db.Writer.Exec("DELETE FROM host_peer_daily WHERE day < ?", cut(ret.PeerDaily)-86400); err != nil {
		return fmt.Errorf("prune host_peer_daily: %w", err)
	}
	if _, err := db.Writer.Exec("DELETE FROM peer_names WHERE last_seen < ?", cut(ret.PeerDaily)); err != nil {
		return fmt.Errorf("prune peer_names: %w", err)
	}
	return nil
}

// IncrementalVacuum runs a bounded incremental vacuum pass.
func (db *DB) IncrementalVacuum() error {
	_, err := db.Writer.Exec("PRAGMA incremental_vacuum")
	return err
}

// HostSeriesFromRollup queries a rollup table for one host's series in [from, to].
// direction filters to a single direction if >= 0, otherwise sums all WAN directions.
func (db *DB) HostSeriesFromRollup(granularity string, hostID int64, from, to int64, direction int) ([]SeriesPoint, error) {
	table, ok := rollupTables[granularity]
	if !ok {
		return nil, fmt.Errorf("unknown granularity %q", granularity)
	}
	query := fmt.Sprintf(
		`SELECT bucket_ts, SUM(bytes_sent), SUM(bytes_recv)
		 FROM %s
		 WHERE host_id = ? AND bucket_ts >= ? AND bucket_ts <= ? AND %s%s
		 GROUP BY bucket_ts
		 ORDER BY bucket_ts`, table, wanDirections, directionClause(direction),
	)
	args := []any{hostID, from, to}
	if direction >= 0 {
		args = append(args, direction)
	}
	return querySeries(db.Reader, query, args...)
}

// SparklineSeries returns one host's recent 1m-rollup points for the
// dashboard sparkline, summed across directions, for the window [from, to].
func (db *DB) SparklineSeries(hostID int64, from, to int64) ([]SeriesPoint, error) {
	return querySeries(db.Reader,
		`SELECT bucket_ts, SUM(bytes_sent), SUM(bytes_recv)
		 FROM rollup_1m
		 WHERE host_id = ? AND bucket_ts >= ? AND bucket_ts <= ? AND `+wanDirections+`
		 GROUP BY bucket_ts
		 ORDER BY bucket_ts`,
		hostID, from, to,
	)
}
