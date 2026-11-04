package store

import "database/sql"

// Setting keys stored in the settings table.
const (
	KeyCaptureInterface  = "capture_interface"
	KeyLANSubnetCIDR     = "lan_subnet_cidr"
	KeyRetentionDays     = "retention_days"
	KeyTLSCertPath       = "tls_cert_path"
	KeyTLSKeyPath        = "tls_key_path"
	KeyHTTPListenAddr    = "http_listen_addr"
	KeyFlushIntervalSecs = "flush_interval_seconds"
	KeySetupComplete     = "setup_complete"
)

// GetSetting returns the value for key, or ("", false) if unset.
func (db *DB) GetSetting(key string) (string, bool, error) {
	var value string
	err := db.Reader.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetSetting upserts a single setting value.
func (db *DB) SetSetting(key, value string) error {
	_, err := db.Writer.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// SetSettings upserts multiple settings in a single transaction.
func (db *DB) SetSettings(kv map[string]string) error {
	tx, err := db.Writer.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, v := range kv {
		if _, err := stmt.Exec(k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AllSettings returns every stored setting as a map.
func (db *DB) AllSettings() (map[string]string, error) {
	rows, err := db.Reader.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
