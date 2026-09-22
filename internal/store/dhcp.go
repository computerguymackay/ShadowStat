package store

import "database/sql"

// UpsertDHCPHostname records a hostname observed via DHCP for mac, and
// propagates it onto any host row(s) already carrying that MAC address —
// done together in one transaction so the two tables never disagree.
func (db *DB) UpsertDHCPHostname(mac, hostname string, seenAt int64) error {
	tx, err := db.Writer.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO dhcp_hostnames (mac_address, hostname, last_seen) VALUES (?, ?, ?)
		 ON CONFLICT(mac_address) DO UPDATE SET hostname = excluded.hostname, last_seen = excluded.last_seen`,
		mac, hostname, seenAt,
	)
	if err != nil {
		return err
	}

	_, err = tx.Exec(
		"UPDATE hosts SET display_name = ? WHERE mac_address = ? AND (display_name IS NULL OR display_name != ?)",
		hostname, mac, hostname,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// HostnameByMAC returns a previously observed DHCP hostname for mac, if any.
func (db *DB) HostnameByMAC(mac string) (string, bool, error) {
	var hostname string
	err := db.Reader.QueryRow("SELECT hostname FROM dhcp_hostnames WHERE mac_address = ?", mac).Scan(&hostname)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hostname, true, nil
}
