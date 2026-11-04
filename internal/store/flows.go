package store

import (
	"database/sql"
	"strings"
)

// Direction values for the direction column of flows_recent, rollup_* and
// host_peer_daily. Since schema v2 this means WHO STARTED the conversation,
// always from the LAN host's point of view. Byte direction is separate:
// bytes_sent is LAN host -> internet, bytes_recv is internet -> LAN host.
//
// v1 stored packet direction here instead (0 = packet from the LAN, 1 =
// packet to the LAN), plus 2/3 for LAN-to-LAN traffic. v1 flows_recent rows
// are relabeled DirUnknown on upgrade; v1 rollup rows keep 0/1, which only
// matters to direction-filtered queries (the UI doesn't make any). Values 2/3
// are never written any more and every query below excludes them.
const (
	DirOutbound = 0 // the LAN host started it (e.g. a browser fetching a page)
	DirInbound  = 1 // the internet peer started it (e.g. a port-forwarded server)
	DirUnknown  = 4 // couldn't tell (conversation already running when first seen, etc.)
)

// wanDirections is the SQL filter that keeps WAN rows and drops the legacy
// v1 LAN-to-LAN directions (2 and 3).
const wanDirections = "direction IN (0, 1, 4)"

// App-protocol confidence levels for app_confidence columns.
const (
	ConfUnknown = 0 // no idea; app_proto is ''
	ConfPort    = 1 // guessed from the port number alone
	ConfPayload = 2 // a payload signature matched
)

// FlowRecord is a flushed, aggregated flow ready to be written to flows_recent.
// Defined here (not in the capture package) so store has no dependency on capture,
// avoiding an import cycle; capture constructs these directly.
type FlowRecord struct {
	HostID        int64
	Direction     int
	Proto         int
	LocalIP       string
	LocalPort     int
	RemoteIP      string
	RemotePort    int
	FirstSeen     int64
	LastSeen      int64
	BytesSent     int64
	BytesRecv     int64
	PacketsSent   int64
	PacketsRecv   int64
	ServicePort   int
	AppProto      string
	AppConfidence int
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
		end := min(start+flowInsertChunk, len(records))
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
		 first_seen, last_seen, bytes_sent, bytes_recv, packets_sent, packets_recv,
		 service_port, app_proto, app_confidence) VALUES `)

	args := make([]any, 0, len(chunk)*16)
	for i, r := range chunk {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
		args = append(args, r.HostID, r.Direction, r.Proto, r.LocalIP, r.LocalPort, r.RemoteIP, r.RemotePort,
			r.FirstSeen, r.LastSeen, r.BytesSent, r.BytesRecv, r.PacketsSent, r.PacketsRecv,
			r.ServicePort, r.AppProto, r.AppConfidence)
	}
	_, err := tx.Exec(sb.String(), args...)
	return err
}

// PruneFlowsRecent deletes flows_recent rows older than cutoff (unix seconds)
// that the rollup job has already processed. Rows past the watermark are
// kept even if old, so a stalled rollup job never loses data.
func (db *DB) PruneFlowsRecent(cutoff int64) error {
	_, err := db.Writer.Exec(
		`DELETE FROM flows_recent WHERE last_seen < ?
		 AND id <= COALESCE((SELECT value FROM rollup_state WHERE name = ?), 0)`,
		cutoff, watermarkKey)
	return err
}

// Conversation is one LAN-host <-> internet-peer conversation (a TCP
// connection, or a UDP/ICMP exchange on one port pair), merged across the
// flush intervals it spanned.
type Conversation struct {
	Direction     int    `json:"direction"`
	Proto         int    `json:"proto"`
	LocalPort     int    `json:"local_port"`
	RemoteIP      string `json:"remote_ip"`
	RemotePort    int    `json:"remote_port"`
	ServicePort   int    `json:"service_port"`
	AppProto      string `json:"app_proto"`
	AppConfidence int    `json:"app_confidence"`
	FirstSeen     int64  `json:"first_seen"`
	LastSeen      int64  `json:"last_seen"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesRecv     int64  `json:"bytes_recv"`
	PacketsSent   int64  `json:"packets_sent"`
	PacketsRecv   int64  `json:"packets_recv"`
}

// HostConversations returns a host's conversations active within [from, to],
// most recently active first. The app_proto reported is the one from the
// row with the highest confidence (SQLite picks bare columns from the MAX row).
func (db *DB) HostConversations(hostID int64, from, to int64, limit int) ([]Conversation, error) {
	rows, err := db.Reader.Query(
		`SELECT MIN(direction), proto, local_port, remote_ip, remote_port, service_port,
		        app_proto, MAX(app_confidence),
		        MIN(first_seen), MAX(last_seen),
		        SUM(bytes_sent), SUM(bytes_recv), SUM(packets_sent), SUM(packets_recv)
		 FROM flows_recent
		 WHERE host_id = ? AND last_seen >= ? AND last_seen <= ? AND `+wanDirections+`
		 GROUP BY proto, local_port, remote_ip, remote_port
		 ORDER BY MAX(last_seen) DESC
		 LIMIT ?`,
		hostID, from, to, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Conversation{}
	for rows.Next() {
		var c Conversation
		if err := rows.Scan(&c.Direction, &c.Proto, &c.LocalPort, &c.RemoteIP, &c.RemotePort, &c.ServicePort,
			&c.AppProto, &c.AppConfidence, &c.FirstSeen, &c.LastSeen,
			&c.BytesSent, &c.BytesRecv, &c.PacketsSent, &c.PacketsRecv); err != nil {
			return nil, err
		}
		out = append(out, c)
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
// direction filters to a single direction if >= 0, otherwise sums all WAN directions.
func (db *DB) HostSeriesFromFlowsRecent(hostID int64, from, to int64, direction int) ([]SeriesPoint, error) {
	query := `SELECT (last_seen/60)*60 AS bucket, SUM(bytes_sent), SUM(bytes_recv)
		 FROM flows_recent
		 WHERE host_id = ? AND last_seen >= ? AND last_seen <= ? AND ` + wanDirections + directionClause(direction) + `
		 GROUP BY bucket
		 ORDER BY bucket`
	args := []any{hostID, from, to}
	if direction >= 0 {
		args = append(args, direction)
	}
	return querySeries(db.Reader, query, args...)
}

func querySeries(q *sql.DB, query string, args ...any) ([]SeriesPoint, error) {
	rows, err := q.Query(query, args...)
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
