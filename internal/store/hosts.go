package store

import "database/sql"

// Host is a LAN device identified by its IP address.
type Host struct {
	ID          int64
	IP          string
	DisplayName sql.NullString
	FirstSeen   int64
	LastSeen    int64
}

// UpsertHost creates a host row for ip if absent, or bumps last_seen if present.
// Returns the host's id.
func (db *DB) UpsertHost(ip string, seenAt int64) (int64, error) {
	_, err := db.Writer.Exec(
		`INSERT INTO hosts (ip, first_seen, last_seen) VALUES (?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen
		 WHERE excluded.last_seen > hosts.last_seen`,
		ip, seenAt, seenAt,
	)
	if err != nil {
		return 0, err
	}
	var id int64
	if err := db.Writer.QueryRow("SELECT id FROM hosts WHERE ip = ?", ip).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// ListHosts returns all known hosts ordered by most recently active first.
func (db *DB) ListHosts() ([]Host, error) {
	rows, err := db.Reader.Query("SELECT id, ip, display_name, first_seen, last_seen FROM hosts ORDER BY last_seen DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.IP, &h.DisplayName, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

// HostByID looks up a single host by id.
func (db *DB) HostByID(id int64) (*Host, error) {
	var h Host
	err := db.Reader.QueryRow(
		"SELECT id, ip, display_name, first_seen, last_seen FROM hosts WHERE id = ?", id,
	).Scan(&h.ID, &h.IP, &h.DisplayName, &h.FirstSeen, &h.LastSeen)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}
