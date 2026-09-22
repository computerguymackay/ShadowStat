package store

import "fmt"

// directionClause returns a SQL fragment filtering on direction when direction
// is a valid value (0/1/2/3), or an empty string to leave rows unfiltered.
func directionClause(direction int) string {
	if direction < 0 {
		return ""
	}
	return " AND direction = ?"
}

// rollupTables maps a granularity name to its table name; also used to validate
// caller-supplied granularity strings before interpolating into SQL.
var rollupTables = map[string]string{
	"1m": "rollup_1m",
	"5m": "rollup_5m",
	"1h": "rollup_1h",
	"1d": "rollup_1d",
}

// RollupFromFlowsRecent computes 1-minute buckets from flows_recent in [from, to)
// and upserts them into rollup_1m, summing on conflict so flows spanning a flush
// boundary don't double- or under-count.
func (db *DB) RollupFromFlowsRecent(from, to int64) error {
	_, err := db.Writer.Exec(
		`INSERT INTO rollup_1m (host_id, direction, bucket_ts, bytes_sent, bytes_recv, packets_sent, packets_recv)
		 SELECT host_id, direction, (last_seen/60)*60 AS bucket_ts,
		        SUM(bytes_sent), SUM(bytes_recv), SUM(packets_sent), SUM(packets_recv)
		 FROM flows_recent
		 WHERE last_seen >= ? AND last_seen < ?
		 GROUP BY host_id, direction, bucket_ts
		 ON CONFLICT (host_id, direction, bucket_ts) DO UPDATE SET
		     bytes_sent = bytes_sent + excluded.bytes_sent,
		     bytes_recv = bytes_recv + excluded.bytes_recv,
		     packets_sent = packets_sent + excluded.packets_sent,
		     packets_recv = packets_recv + excluded.packets_recv`,
		from, to,
	)
	return err
}

// RollupFromFiner aggregates srcGranularity buckets in [from, to) up into dstGranularity
// buckets of width bucketWidth seconds, upserting with sum-on-conflict.
func (db *DB) RollupFromFiner(srcGranularity, dstGranularity string, bucketWidth, from, to int64) error {
	srcTable, ok := rollupTables[srcGranularity]
	if !ok {
		return fmt.Errorf("unknown source granularity %q", srcGranularity)
	}
	dstTable, ok := rollupTables[dstGranularity]
	if !ok {
		return fmt.Errorf("unknown dest granularity %q", dstGranularity)
	}

	query := fmt.Sprintf(
		`INSERT INTO %s (host_id, direction, bucket_ts, bytes_sent, bytes_recv, packets_sent, packets_recv)
		 SELECT host_id, direction, (bucket_ts/%d)*%d AS bucket_ts,
		        SUM(bytes_sent), SUM(bytes_recv), SUM(packets_sent), SUM(packets_recv)
		 FROM %s
		 WHERE bucket_ts >= ? AND bucket_ts < ?
		 GROUP BY host_id, direction, bucket_ts
		 ON CONFLICT (host_id, direction, bucket_ts) DO UPDATE SET
		     bytes_sent = bytes_sent + excluded.bytes_sent,
		     bytes_recv = bytes_recv + excluded.bytes_recv,
		     packets_sent = packets_sent + excluded.packets_sent,
		     packets_recv = packets_recv + excluded.packets_recv`,
		dstTable, bucketWidth, bucketWidth, srcTable,
	)
	_, err := db.Writer.Exec(query, from, to)
	return err
}

// PruneRollup deletes rows older than cutoff from the given granularity's table.
func (db *DB) PruneRollup(granularity string, cutoff int64) error {
	table, ok := rollupTables[granularity]
	if !ok {
		return fmt.Errorf("unknown granularity %q", granularity)
	}
	_, err := db.Writer.Exec(fmt.Sprintf("DELETE FROM %s WHERE bucket_ts < ?", table), cutoff)
	return err
}

// IncrementalVacuum runs a bounded incremental vacuum pass.
func (db *DB) IncrementalVacuum() error {
	_, err := db.Writer.Exec("PRAGMA incremental_vacuum")
	return err
}

// HostSeriesFromRollup queries a rollup table for one host's series in [from, to].
// direction filters to a single direction (0/1/2/3) if >= 0, otherwise sums all directions.
func (db *DB) HostSeriesFromRollup(granularity string, hostID int64, from, to int64, direction int) ([]SeriesPoint, error) {
	table, ok := rollupTables[granularity]
	if !ok {
		return nil, fmt.Errorf("unknown granularity %q", granularity)
	}
	query := fmt.Sprintf(
		`SELECT bucket_ts, SUM(bytes_sent), SUM(bytes_recv)
		 FROM %s
		 WHERE host_id = ? AND bucket_ts >= ? AND bucket_ts <= ?%s
		 GROUP BY bucket_ts
		 ORDER BY bucket_ts`, table, directionClause(direction),
	)
	args := []any{hostID, from, to}
	if direction >= 0 {
		args = append(args, direction)
	}
	rows, err := db.Reader.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SeriesPoint
	for rows.Next() {
		var p SeriesPoint
		if err := rows.Scan(&p.BucketTS, &p.BytesSent, &p.BytesRecv); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SparklineSeries returns recent 1m-rollup points across all hosts for dashboard sparklines,
// summed across direction, for the window [from, to].
func (db *DB) SparklineSeries(hostID int64, from, to int64) ([]SeriesPoint, error) {
	rows, err := db.Reader.Query(
		`SELECT bucket_ts, SUM(bytes_sent), SUM(bytes_recv)
		 FROM rollup_1m
		 WHERE host_id = ? AND bucket_ts >= ? AND bucket_ts <= ?
		 GROUP BY bucket_ts
		 ORDER BY bucket_ts`,
		hostID, from, to,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SeriesPoint
	for rows.Next() {
		var p SeriesPoint
		if err := rows.Scan(&p.BucketTS, &p.BytesSent, &p.BytesRecv); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
