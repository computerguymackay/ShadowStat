package store

// Read-only queries used exclusively by internal/detect's detectors. Kept
// separate from flows.go's core CRUD to make clear these are detector-specific
// analytical views over flows_recent, not part of the base flow storage API.

// PeerFlowTimestamp is one flow observation's start time for a (host, remote
// peer) pair, used by the beaconing detector to compute inter-arrival intervals.
type PeerFlowTimestamp struct {
	HostID     int64
	RemoteIP   string
	RemotePort int
	FirstSeen  int64
}

// PeerFlowTimestamps returns every flows_recent row's (host, peer, first_seen)
// in [since, now], ordered so each (host, peer) group's timestamps are
// naturally in ascending order for interval analysis.
func (db *DB) PeerFlowTimestamps(since, now int64) ([]PeerFlowTimestamp, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, remote_ip, remote_port, first_seen
		 FROM flows_recent
		 WHERE last_seen >= ? AND last_seen <= ?
		 ORDER BY host_id, remote_ip, remote_port, first_seen`,
		since, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PeerFlowTimestamp
	for rows.Next() {
		var p PeerFlowTimestamp
		if err := rows.Scan(&p.HostID, &p.RemoteIP, &p.RemotePort, &p.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// HostByteTotals is one host's LAN->WAN byte totals over a scan window.
type HostByteTotals struct {
	HostID    int64
	BytesSent int64
	BytesRecv int64
}

// HostOutboundTotals returns each host's LAN->WAN sent/received byte totals in
// [since, now], used by the upload/download ratio (exfiltration) detector.
func (db *DB) HostOutboundTotals(since, now int64) ([]HostByteTotals, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, SUM(bytes_sent), SUM(bytes_recv)
		 FROM flows_recent
		 WHERE direction = ? AND last_seen >= ? AND last_seen <= ?
		 GROUP BY host_id`,
		DirLANToWAN, since, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HostByteTotals
	for rows.Next() {
		var h HostByteTotals
		if err := rows.Scan(&h.HostID, &h.BytesSent, &h.BytesRecv); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// HostDistinctPeerCount is a host's count of distinct remote (ip, port) pairs
// contacted within a scan window, used by the port-scan detector.
type HostDistinctPeerCount struct {
	HostID int64
	Count  int
}

// HostDistinctPeerCounts returns, for every host with LAN->WAN activity in
// [since, now], how many distinct remote (ip, port) pairs it contacted.
func (db *DB) HostDistinctPeerCounts(since, now int64) ([]HostDistinctPeerCount, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, COUNT(*) FROM (
		     SELECT DISTINCT host_id, remote_ip, remote_port
		     FROM flows_recent
		     WHERE direction = ? AND last_seen >= ? AND last_seen <= ?
		 ) GROUP BY host_id`,
		DirLANToWAN, since, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HostDistinctPeerCount
	for rows.Next() {
		var c HostDistinctPeerCount
		if err := rows.Scan(&c.HostID, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
