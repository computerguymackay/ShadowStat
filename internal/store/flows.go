package store

import (
	"database/sql"
	"strings"
)

// Direction values for flows_recent.direction / rollup_*.direction.
const (
	DirLANToWAN  = 0
	DirWANToLAN  = 1
	DirInterVLAN = 2
)

// FlowRecord is a flushed, aggregated flow ready to be written to flows_recent.
// Defined here (not in the capture package) so store has no dependency on capture,
// avoiding an import cycle; capture constructs these directly.
type FlowRecord struct {
	HostID      int64
	Direction   int
	Proto       int
	LocalIP     string
	LocalPort   int
	RemoteIP    string
	RemotePort  int
	FirstSeen   int64
	LastSeen    int64
	BytesSent   int64
	BytesRecv   int64
	PacketsSent int64
	PacketsRecv int64
}

const flowInsertChunk = 500

// InsertFlows batch-inserts flow records in chunks within a single transaction.
func (db *DB) InsertFlows(records []FlowRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := db.Writer.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for start := 0; start < len(records); start += flowInsertChunk {
		end := start + flowInsertChunk
		if end > len(records) {
			end = len(records)
		}
		if err := insertFlowChunk(tx, records[start:end]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertFlowChunk(tx *sql.Tx, chunk []FlowRecord) error {
	var sb strings.Builder
	sb.WriteString(`INSERT INTO flows_recent
		(host_id, direction, proto, local_ip, local_port, remote_ip, remote_port,
		 first_seen, last_seen, bytes_sent, bytes_recv, packets_sent, packets_recv) VALUES `)

	args := make([]any, 0, len(chunk)*13)
	for i, r := range chunk {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?,?)")
		args = append(args, r.HostID, r.Direction, r.Proto, r.LocalIP, r.LocalPort, r.RemoteIP, r.RemotePort,
			r.FirstSeen, r.LastSeen, r.BytesSent, r.BytesRecv, r.PacketsSent, r.PacketsRecv)
	}
	_, err := tx.Exec(sb.String(), args...)
	return err
}

// PruneFlowsRecent deletes flows_recent rows older than cutoff (unix seconds).
func (db *DB) PruneFlowsRecent(cutoff int64) error {
	_, err := db.Writer.Exec("DELETE FROM flows_recent WHERE last_seen < ?", cutoff)
	return err
}

// FlowDetail is one row of per-flow detail for the flows table UI.
type FlowDetail struct {
	RemoteIP    string
	RemotePort  int
	Proto       int
	Direction   int
	FirstSeen   int64
	LastSeen    int64
	BytesSent   int64
	BytesRecv   int64
	PacketsSent int64
	PacketsRecv int64
}

// HostFlows returns per-flow detail rows for a host within [from, to], most recent first.
func (db *DB) HostFlows(hostID int64, from, to int64, limit int) ([]FlowDetail, error) {
	rows, err := db.Reader.Query(
		`SELECT remote_ip, remote_port, proto, direction, first_seen, last_seen,
		        bytes_sent, bytes_recv, packets_sent, packets_recv
		 FROM flows_recent
		 WHERE host_id = ? AND last_seen >= ? AND last_seen <= ?
		 ORDER BY last_seen DESC
		 LIMIT ?`,
		hostID, from, to, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FlowDetail
	for rows.Next() {
		var f FlowDetail
		if err := rows.Scan(&f.RemoteIP, &f.RemotePort, &f.Proto, &f.Direction, &f.FirstSeen, &f.LastSeen,
			&f.BytesSent, &f.BytesRecv, &f.PacketsSent, &f.PacketsRecv); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SeriesPoint is one bucket of a time series (used for both on-the-fly and rollup queries).
type SeriesPoint struct {
	BucketTS  int64
	BytesSent int64
	BytesRecv int64
}

// HostSeriesFromFlowsRecent aggregates flows_recent on the fly into minute buckets,
// used for the most recent 24h where rollup_1m may not yet cover the full range.
// direction filters to a single direction (0/1/2) if >= 0, otherwise sums all directions.
func (db *DB) HostSeriesFromFlowsRecent(hostID int64, from, to int64, direction int) ([]SeriesPoint, error) {
	query := `SELECT (last_seen/60)*60 AS bucket, SUM(bytes_sent), SUM(bytes_recv)
		 FROM flows_recent
		 WHERE host_id = ? AND last_seen >= ? AND last_seen <= ?` + directionClause(direction) + `
		 GROUP BY bucket
		 ORDER BY bucket`
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
