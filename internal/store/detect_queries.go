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

// TargetPortScan is one (host, single remote IP) pair where the host
// contacted an unusually large number of distinct ports on that one target —
// the actual signature of a port scan, as opposed to contacting many
// different hosts (which is normal multi-service browsing/app traffic and
// was previously conflated with scanning, causing false positives).
type TargetPortScan struct {
	HostID    int64
	RemoteIP  string
	PortsCSV  string // comma-separated distinct remote ports, via GROUP_CONCAT; caller parses
	PortCount int
}

// HostTargetPortScans returns, for every (host, remote IP) pair in [since,
// now] where the host contacted at least minPorts distinct ports on that one
// remote IP, the port count and the actual port list (capped to a reasonable
// size by the caller after parsing PortsCSV).
func (db *DB) HostTargetPortScans(since, now int64, minPorts int) ([]TargetPortScan, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, remote_ip, COUNT(DISTINCT remote_port) AS port_count, GROUP_CONCAT(DISTINCT remote_port)
		 FROM flows_recent
		 WHERE direction = ? AND last_seen >= ? AND last_seen <= ?
		 GROUP BY host_id, remote_ip
		 HAVING port_count >= ?`,
		DirLANToWAN, since, now, minPorts,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TargetPortScan
	for rows.Next() {
		var t TargetPortScan
		if err := rows.Scan(&t.HostID, &t.RemoteIP, &t.PortCount, &t.PortsCSV); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
