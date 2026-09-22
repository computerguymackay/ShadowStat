package store

import "database/sql"

// Host is a LAN device identified by its IP address.
type Host struct {
	ID          int64
	IP          string
	DisplayName sql.NullString
	MACAddress  sql.NullString
	FirstSeen   int64
	LastSeen    int64
}

// UpsertHost creates a host row for ip if absent, or bumps last_seen if the
// new timestamp is more recent. Returns the host's id in a single round trip.
func (db *DB) UpsertHost(ip string, seenAt int64) (int64, error) {
	var id int64
	err := db.Writer.QueryRow(
		`INSERT INTO hosts (ip, first_seen, last_seen) VALUES (?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET last_seen = MAX(hosts.last_seen, excluded.last_seen)
		 RETURNING id`,
		ip, seenAt, seenAt,
	).Scan(&id)
	return id, err
}

// SetHostMAC records (or updates) a host's observed MAC address.
func (db *DB) SetHostMAC(hostID int64, mac string) error {
	_, err := db.Writer.Exec("UPDATE hosts SET mac_address = ? WHERE id = ? AND (mac_address IS NULL OR mac_address != ?)", mac, hostID, mac)
	return err
}

// SetHostDisplayNameByMAC updates display_name for every host currently
// recorded with the given MAC address — used when a DHCP-observed hostname
// is learned, since it may arrive before or after the host's own IP traffic.
func (db *DB) SetHostDisplayNameByMAC(mac, hostname string) error {
	_, err := db.Writer.Exec(
		"UPDATE hosts SET display_name = ? WHERE mac_address = ? AND (display_name IS NULL OR display_name != ?)",
		hostname, mac, hostname,
	)
	return err
}

// ListHosts returns all known hosts ordered by most recently active first.
func (db *DB) ListHosts() ([]Host, error) {
	rows, err := db.Reader.Query("SELECT id, ip, display_name, mac_address, first_seen, last_seen FROM hosts ORDER BY last_seen DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.IP, &h.DisplayName, &h.MACAddress, &h.FirstSeen, &h.LastSeen); err != nil {
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
		"SELECT id, ip, display_name, mac_address, first_seen, last_seen FROM hosts WHERE id = ?", id,
	).Scan(&h.ID, &h.IP, &h.DisplayName, &h.MACAddress, &h.FirstSeen, &h.LastSeen)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}
