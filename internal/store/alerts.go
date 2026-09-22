package store

// Alert kinds, matching internal/detect's detectors.
const (
	AlertKindNewDestination = "new_destination"
	AlertKindBeaconing      = "beaconing"
	AlertKindExfilRatio     = "exfil_ratio"
	AlertKindDNSAnomaly     = "dns_anomaly"
	AlertKindPortScan       = "port_scan"
)

// Alert severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// AlertRecord is a new alert to be inserted by a detector.
type AlertRecord struct {
	HostID     int64
	Kind       string
	Severity   string
	Summary    string
	Detail     string // free-form (typically JSON) detector-specific context
	DedupeKey  string // used with RecentAlertExists to avoid re-alerting the same condition repeatedly
	DetectedAt int64
}

// Alert is a stored alert, joined with its host's IP for display.
type Alert struct {
	ID           int64
	HostID       int64
	HostIP       string
	Kind         string
	Severity     string
	Summary      string
	Detail       string
	DetectedAt   int64
	Acknowledged bool
}

// RecentAlertExists reports whether an alert of the given kind+dedupeKey for
// hostID was already raised at or after since, letting detectors avoid
// re-alerting on an ongoing condition every time they run.
func (db *DB) RecentAlertExists(hostID int64, kind, dedupeKey string, since int64) (bool, error) {
	var count int
	err := db.Reader.QueryRow(
		`SELECT COUNT(*) FROM alerts
		 WHERE host_id = ? AND kind = ? AND dedupe_key = ? AND detected_at >= ?`,
		hostID, kind, dedupeKey, since,
	).Scan(&count)
	return count > 0, err
}

// InsertAlert records a new alert.
func (db *DB) InsertAlert(a AlertRecord) error {
	_, err := db.Writer.Exec(
		`INSERT INTO alerts (host_id, kind, severity, summary, detail, dedupe_key, detected_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.HostID, a.Kind, a.Severity, a.Summary, a.Detail, a.DedupeKey, a.DetectedAt,
	)
	return err
}

const alertListColumns = `a.id, a.host_id, h.ip, a.kind, a.severity, a.summary, a.detail, a.detected_at, a.acknowledged`

func scanAlerts(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]Alert, error) {
	var out []Alert
	for rows.Next() {
		var a Alert
		var ack int
		if err := rows.Scan(&a.ID, &a.HostID, &a.HostIP, &a.Kind, &a.Severity, &a.Summary, &a.Detail, &a.DetectedAt, &ack); err != nil {
			return nil, err
		}
		a.Acknowledged = ack != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAlerts returns the most recent alerts across all hosts, most recent first.
// If unackedOnly is true, acknowledged alerts are excluded.
func (db *DB) ListAlerts(limit int, unackedOnly bool) ([]Alert, error) {
	query := `SELECT ` + alertListColumns + ` FROM alerts a JOIN hosts h ON h.id = a.host_id`
	if unackedOnly {
		query += ` WHERE a.acknowledged = 0`
	}
	query += ` ORDER BY a.detected_at DESC LIMIT ?`

	rows, err := db.Reader.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlerts(rows)
}

// ListAlertsForHost returns the most recent alerts for a single host.
func (db *DB) ListAlertsForHost(hostID int64, limit int) ([]Alert, error) {
	rows, err := db.Reader.Query(
		`SELECT `+alertListColumns+` FROM alerts a JOIN hosts h ON h.id = a.host_id
		 WHERE a.host_id = ? ORDER BY a.detected_at DESC LIMIT ?`,
		hostID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlerts(rows)
}

// AcknowledgeAlert marks an alert as acknowledged.
func (db *DB) AcknowledgeAlert(id int64) error {
	_, err := db.Writer.Exec("UPDATE alerts SET acknowledged = 1 WHERE id = ?", id)
	return err
}

// CountUnacknowledgedAlerts returns how many alerts are still unacknowledged,
// used for a nav badge.
func (db *DB) CountUnacknowledgedAlerts() (int, error) {
	var count int
	err := db.Reader.QueryRow("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").Scan(&count)
	return count, err
}
