package store

import (
	"database/sql"
	"strconv"
	"strings"
)

// Read queries behind the dashboard and host page: who a host talks to,
// on which ports and protocols, and how much.
//
// Ranges inside the last 24h are answered exactly from flows_recent. Older
// ranges come from host_peer_daily, which has whole-UTC-day resolution, so
// the range is widened to the days it touches (Breakdown.DayResolution).

// Breakdown is a host's traffic over a time range, grouped two ways.
type Breakdown struct {
	DayResolution bool         `json:"day_resolution"`
	Peers         []PeerRow    `json:"peers"`
	Services      []ServiceRow `json:"services"`
}

// PeerRow is one remote peer a host exchanged traffic with.
type PeerRow struct {
	RemoteIP  string   `json:"remote_ip"`
	Name      string   `json:"name,omitempty"`    // from DNS answers, if seen
	Country   string   `json:"country,omitempty"` // filled in by the web layer
	Protocols []string `json:"protocols"`         // app protocols seen ('' = unknown)
	Ports     []int    `json:"ports"`             // service ports seen
	StartedBy string   `json:"started_by"`        // "host", "remote", "both" or "unknown"
	BytesSent int64    `json:"bytes_sent"`
	BytesRecv int64    `json:"bytes_recv"`
}

// ServiceRow is one (L4 protocol, service port, app protocol) combination.
type ServiceRow struct {
	Proto         int    `json:"proto"`
	ServicePort   int    `json:"service_port"`
	AppProto      string `json:"app_proto"`
	AppConfidence int    `json:"app_confidence"`
	StartedBy     string `json:"started_by"`
	Peers         int    `json:"peers"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesRecv     int64  `json:"bytes_recv"`
}

// HostBreakdown returns the top `limit` peers and services for a host in
// [from, to], biggest total bytes first. recentCutoff is the oldest time
// flows_recent still fully covers (normally now - 24h).
func (db *DB) HostBreakdown(hostID, from, to, recentCutoff int64, limit int) (*Breakdown, error) {
	b := &Breakdown{Peers: []PeerRow{}, Services: []ServiceRow{}}

	var source string
	var args []any
	if from >= recentCutoff {
		source = `(SELECT remote_ip, proto, service_port, app_proto, app_confidence, direction,
		                  bytes_sent, bytes_recv
		           FROM flows_recent
		           WHERE host_id = ? AND last_seen >= ? AND last_seen <= ? AND ` + wanDirections + `)`
		args = []any{hostID, from, to}
	} else {
		b.DayResolution = true
		source = `(SELECT remote_ip, proto, service_port, app_proto, app_confidence, direction,
		                  bytes_sent, bytes_recv
		           FROM host_peer_daily
		           WHERE host_id = ? AND day >= ? AND day <= ?)`
		args = []any{hostID, (from / 86400) * 86400, to}
	}

	startedBy := `MAX(direction = 0), MAX(direction = 1), MAX(direction = 4)`

	peerRows, err := db.Reader.Query(
		`SELECT p.*, COALESCE(n.name, '') FROM (
		     SELECT remote_ip, SUM(bytes_sent) s, SUM(bytes_recv) r,
		            GROUP_CONCAT(DISTINCT app_proto), GROUP_CONCAT(DISTINCT service_port), `+startedBy+`
		     FROM `+source+`
		     GROUP BY remote_ip
		     ORDER BY s + r DESC
		     LIMIT ?
		 ) p LEFT JOIN peer_names n ON n.ip = p.remote_ip
		 ORDER BY p.s + p.r DESC`,
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer peerRows.Close()
	for peerRows.Next() {
		var p PeerRow
		var protos, ports sql.NullString
		var out, in, unk bool
		if err := peerRows.Scan(&p.RemoteIP, &p.BytesSent, &p.BytesRecv, &protos, &ports, &out, &in, &unk, &p.Name); err != nil {
			return nil, err
		}
		p.Protocols = splitCSV(protos.String)
		p.Ports = splitInts(ports.String)
		p.StartedBy = startedByLabel(out, in, unk)
		b.Peers = append(b.Peers, p)
	}
	if err := peerRows.Err(); err != nil {
		return nil, err
	}

	svcRows, err := db.Reader.Query(
		`SELECT proto, service_port, app_proto, MAX(app_confidence),
		        COUNT(DISTINCT remote_ip), SUM(bytes_sent) s, SUM(bytes_recv) r, `+startedBy+`
		 FROM `+source+`
		 GROUP BY proto, service_port, app_proto
		 ORDER BY s + r DESC
		 LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer svcRows.Close()
	for svcRows.Next() {
		var s ServiceRow
		var out, in, unk bool
		if err := svcRows.Scan(&s.Proto, &s.ServicePort, &s.AppProto, &s.AppConfidence,
			&s.Peers, &s.BytesSent, &s.BytesRecv, &out, &in, &unk); err != nil {
			return nil, err
		}
		s.StartedBy = startedByLabel(out, in, unk)
		b.Services = append(b.Services, s)
	}
	return b, svcRows.Err()
}

func startedByLabel(out, in, unknown bool) string {
	switch {
	case out && in:
		return "both"
	case out:
		return "host"
	case in:
		return "remote"
	default:
		return "unknown"
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}

func splitInts(s string) []int {
	out := []int{}
	for _, part := range splitCSV(s) {
		if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// HostTotals is a host's cumulative counters (see the host_totals table).
type HostTotals struct {
	HostID      int64
	BytesSent   int64
	BytesRecv   int64
	PacketsSent int64
	PacketsRecv int64
	TotalsSince int64
	ExactSince  sql.NullInt64
}

// AllHostTotals returns host_totals keyed by host id. One row per host, so
// this is cheap even though it reads the whole table.
func (db *DB) AllHostTotals() (map[int64]HostTotals, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, bytes_sent, bytes_recv, packets_sent, packets_recv, totals_since, exact_since FROM host_totals`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HostTotals{}
	for rows.Next() {
		var t HostTotals
		if err := rows.Scan(&t.HostID, &t.BytesSent, &t.BytesRecv, &t.PacketsSent, &t.PacketsRecv, &t.TotalsSince, &t.ExactSince); err != nil {
			return nil, err
		}
		out[t.HostID] = t
	}
	return out, rows.Err()
}

// HostTotalsByID returns one host's cumulative counters, or ok=false if no
// traffic has been rolled up for it yet.
func (db *DB) HostTotalsByID(hostID int64) (HostTotals, bool, error) {
	var t HostTotals
	err := db.Reader.QueryRow(
		`SELECT host_id, bytes_sent, bytes_recv, packets_sent, packets_recv, totals_since, exact_since
		 FROM host_totals WHERE host_id = ?`, hostID,
	).Scan(&t.HostID, &t.BytesSent, &t.BytesRecv, &t.PacketsSent, &t.PacketsRecv, &t.TotalsSince, &t.ExactSince)
	if err == sql.ErrNoRows {
		return t, false, nil
	}
	return t, err == nil, err
}

// ByteCounts is a sent/received pair.
type ByteCounts struct {
	Sent int64
	Recv int64
}

// HostTrafficSince returns each host's sent/received bytes from rollup_1m
// buckets starting at or after since (used for "last 24h" on the dashboard).
func (db *DB) HostTrafficSince(since int64) (map[int64]ByteCounts, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, SUM(bytes_sent), SUM(bytes_recv) FROM rollup_1m
		 WHERE bucket_ts >= ? AND `+wanDirections+` GROUP BY host_id`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]ByteCounts{}
	for rows.Next() {
		var id int64
		var c ByteCounts
		if err := rows.Scan(&id, &c.Sent, &c.Recv); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}

// TopProtocols returns, per host, up to n app protocols by total bytes from
// host_peer_daily days starting at or after sinceDay. Unknown traffic is
// reported as "".
func (db *DB) TopProtocols(sinceDay int64, n int) (map[int64][]string, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, app_proto FROM host_peer_daily
		 WHERE day >= ?
		 GROUP BY host_id, app_proto
		 ORDER BY host_id, SUM(bytes_sent + bytes_recv) DESC`, sinceDay)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var proto string
		if err := rows.Scan(&id, &proto); err != nil {
			return nil, err
		}
		if len(out[id]) < n {
			out[id] = append(out[id], proto)
		}
	}
	return out, rows.Err()
}
