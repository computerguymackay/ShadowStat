package store

import "database/sql"

// PeerName is a remote IP's hostname, as learned from a DNS answer.
type PeerName struct {
	IP       string
	Name     string
	LastSeen int64
}

// UpsertPeerNames records learned names in one transaction. A newer answer
// for the same IP replaces the older name.
func (db *DB) UpsertPeerNames(names []PeerName) error {
	if len(names) == 0 {
		return nil
	}
	tx, err := db.Writer.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO peer_names (ip, name, last_seen) VALUES (?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET name = excluded.name, last_seen = excluded.last_seen
		 WHERE excluded.last_seen >= peer_names.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, n := range names {
		if _, err := stmt.Exec(n.IP, n.Name, n.LastSeen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PeerNameFor returns the learned name for ip, or "" if none.
func (db *DB) PeerNameFor(ip string) (string, error) {
	var name string
	err := db.Reader.QueryRow("SELECT name FROM peer_names WHERE ip = ?", ip).Scan(&name)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return name, err
}
