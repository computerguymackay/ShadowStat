package store

import (
	"database/sql"
	"fmt"
)

// migrateV1ToV2 upgrades a v1 database in one transaction:
//
//  1. v1 flows_recent rows recorded packet direction, not who started the
//     conversation, so their direction becomes DirUnknown. Their service
//     port is guessed as the lower of the two ports. Legacy LAN-to-LAN rows
//     (direction 2/3) are left alone; every v2 query ignores them.
//  2. host_totals is seeded from the existing rollups, using each tier only
//     for the time the coarser tiers don't cover, so nothing is counted twice.
//  3. host_peer_daily is seeded from what is left in flows_recent (≤24h).
//  4. The rollup watermark is set to the newest flows_recent row, since the
//     v1 rollup job already folded those rows into the rollup tiers.
//
// Re-running it (after a manual rollback that resets schema_meta to 1)
// recomputes host_totals and the affected host_peer_daily days from scratch
// rather than adding to them. v2 rows are relabeled "unknown" too in that
// case, since they can't be told apart from v1 rows.
func (db *DB) migrateV1ToV2(now int64) error {
	tx, err := db.Writer.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE flows_recent
		SET direction = ?,
		    service_port = CASE
		        WHEN local_port = 0 OR remote_port = 0 THEN 0
		        WHEN local_port < remote_port THEN local_port
		        ELSE remote_port END
		WHERE direction IN (0, 1)`, DirUnknown); err != nil {
		return fmt.Errorf("relabel flows_recent: %w", err)
	}

	// Coverage boundaries: rollup_1h covers [0, b1h), rollup_5m [b1h, b5m),
	// rollup_1m [b5m, b1m) and flows_recent the rest. Each boundary stops at
	// the start of the current bucket, so a bucket still being filled is
	// taken from the next finer tier instead.
	b1h, err := tierEnd(tx, "rollup_1h", 3600, 0, now)
	if err != nil {
		return err
	}
	b5m, err := tierEnd(tx, "rollup_5m", 300, b1h, now)
	if err != nil {
		return err
	}
	b1m, err := tierEnd(tx, "rollup_1m", 60, b5m, now)
	if err != nil {
		return err
	}

	if _, err := tx.Exec("DELETE FROM host_totals"); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO host_totals
		(host_id, bytes_sent, bytes_recv, packets_sent, packets_recv, totals_since, exact_since)
		SELECT host_id, SUM(bs), SUM(br), SUM(ps), SUM(pr), MIN(since), ?
		FROM (
		    SELECT host_id, bytes_sent bs, bytes_recv br, packets_sent ps, packets_recv pr, bucket_ts since
		      FROM rollup_1h WHERE `+wanDirections+` AND bucket_ts < ?
		    UNION ALL
		    SELECT host_id, bytes_sent, bytes_recv, packets_sent, packets_recv, bucket_ts
		      FROM rollup_5m WHERE `+wanDirections+` AND bucket_ts >= ? AND bucket_ts < ?
		    UNION ALL
		    SELECT host_id, bytes_sent, bytes_recv, packets_sent, packets_recv, bucket_ts
		      FROM rollup_1m WHERE `+wanDirections+` AND bucket_ts >= ? AND bucket_ts < ?
		    UNION ALL
		    SELECT host_id, bytes_sent, bytes_recv, packets_sent, packets_recv, first_seen
		      FROM flows_recent WHERE direction = ? AND last_seen >= ?
		)
		GROUP BY host_id`,
		now, b1h, b1h, b5m, b5m, b1m, DirUnknown, b1m); err != nil {
		return fmt.Errorf("backfill host_totals: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM host_peer_daily
		WHERE day >= (SELECT COALESCE(MIN((last_seen/86400)*86400), 1 << 62) FROM flows_recent)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO host_peer_daily
		(host_id, day, remote_ip, proto, service_port, app_proto, direction,
		 bytes_sent, bytes_recv, packets_sent, packets_recv)
		SELECT host_id, (last_seen/86400)*86400, remote_ip, proto, service_port, '', ?,
		       SUM(bytes_sent), SUM(bytes_recv), SUM(packets_sent), SUM(packets_recv)
		FROM flows_recent WHERE direction = ?
		GROUP BY host_id, (last_seen/86400)*86400, remote_ip, proto, service_port`,
		DirUnknown, DirUnknown); err != nil {
		return fmt.Errorf("backfill host_peer_daily: %w", err)
	}

	if _, err := tx.Exec(`INSERT INTO rollup_state (name, value)
		SELECT ?, COALESCE(MAX(id), 0) FROM flows_recent WHERE true
		ON CONFLICT(name) DO UPDATE SET value = excluded.value`, watermarkKey); err != nil {
		return fmt.Errorf("set rollup watermark: %w", err)
	}

	if _, err := tx.Exec("UPDATE schema_meta SET version = 2"); err != nil {
		return err
	}
	return tx.Commit()
}

// tierEnd returns where a rollup table's coverage ends: the end of its
// newest bucket, but no later than the start of the bucket now falls in
// (that one may still be filling) and no earlier than floor.
func tierEnd(tx *sql.Tx, table string, width, floor, now int64) (int64, error) {
	var maxTS sql.NullInt64
	if err := tx.QueryRow(fmt.Sprintf("SELECT MAX(bucket_ts) FROM %s WHERE %s", table, wanDirections)).Scan(&maxTS); err != nil {
		return 0, fmt.Errorf("scan %s: %w", table, err)
	}
	if !maxTS.Valid {
		return floor, nil
	}
	end := min(maxTS.Int64+width, (now/width)*width)
	return max(end, floor), nil
}
