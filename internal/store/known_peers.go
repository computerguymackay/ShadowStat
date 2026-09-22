package store

import "database/sql"

// KnownPeerLastSeen returns the last_seen timestamp for a (host, remote peer)
// pair if it has been observed before.
func (db *DB) KnownPeerLastSeen(hostID int64, remoteIP string, remotePort int) (int64, bool, error) {
	var lastSeen int64
	err := db.Reader.QueryRow(
		"SELECT last_seen FROM known_peers WHERE host_id = ? AND remote_ip = ? AND remote_port = ?",
		hostID, remoteIP, remotePort,
	).Scan(&lastSeen)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return lastSeen, err == nil, err
}

// UpsertKnownPeer records (or bumps) a (host, remote peer) pair's last_seen.
func (db *DB) UpsertKnownPeer(hostID int64, remoteIP string, remotePort int, seenAt int64) error {
	_, err := db.Writer.Exec(
		`INSERT INTO known_peers (host_id, remote_ip, remote_port, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(host_id, remote_ip, remote_port) DO UPDATE SET last_seen = excluded.last_seen`,
		hostID, remoteIP, remotePort, seenAt, seenAt,
	)
	return err
}

// DistinctRecentPeer is one (host, remote peer) pair first contacted within a
// detector's scan window, used by the new-destination detector. HadOutbound/
// HadInbound distinguish whether the pair's traffic in the window included
// this host initiating contact (LAN->WAN), the peer reaching in (WAN->LAN),
// or both (the common case for a normal request/response) — so an alert can
// say which actually happened instead of leaving it ambiguous.
type DistinctRecentPeer struct {
	HostID      int64
	RemoteIP    string
	RemotePort  int
	FirstSeen   int64
	HadOutbound bool
	HadInbound  bool
}

// RecentFlowPeers returns the distinct (host, remote peer) pairs with any
// flows_recent activity in [since, now], across all directions.
func (db *DB) RecentFlowPeers(since, now int64) ([]DistinctRecentPeer, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, remote_ip, remote_port, MIN(first_seen),
		        MAX(CASE WHEN direction = ? THEN 1 ELSE 0 END),
		        MAX(CASE WHEN direction = ? THEN 1 ELSE 0 END)
		 FROM flows_recent
		 WHERE last_seen >= ? AND last_seen <= ?
		 GROUP BY host_id, remote_ip, remote_port`,
		DirLANToWAN, DirWANToLAN, since, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DistinctRecentPeer
	for rows.Next() {
		var p DistinctRecentPeer
		var hadOutbound, hadInbound int
		if err := rows.Scan(&p.HostID, &p.RemoteIP, &p.RemotePort, &p.FirstSeen, &hadOutbound, &hadInbound); err != nil {
			return nil, err
		}
		p.HadOutbound, p.HadInbound = hadOutbound != 0, hadInbound != 0
		out = append(out, p)
	}
	return out, rows.Err()
}
