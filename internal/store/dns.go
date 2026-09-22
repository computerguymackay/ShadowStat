package store

import "strings"

// DNSQueryRecord is one observed DNS query, ready for batch insert.
type DNSQueryRecord struct {
	HostID int64
	QName  string
	QType  int
	TS     int64
}

const dnsInsertChunk = 500

// InsertDNSQueries batch-inserts DNS query records in chunks within a single transaction.
func (db *DB) InsertDNSQueries(records []DNSQueryRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := db.Writer.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for start := 0; start < len(records); start += dnsInsertChunk {
		end := start + dnsInsertChunk
		if end > len(records) {
			end = len(records)
		}
		var sb strings.Builder
		sb.WriteString("INSERT INTO dns_queries (host_id, qname, qtype, ts) VALUES ")
		args := make([]any, 0, (end-start)*4)
		for i, r := range records[start:end] {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?)")
			args = append(args, r.HostID, r.QName, r.QType, r.TS)
		}
		if _, err := tx.Exec(sb.String(), args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneDNSQueries deletes dns_queries rows older than cutoff.
func (db *DB) PruneDNSQueries(cutoff int64) error {
	_, err := db.Writer.Exec("DELETE FROM dns_queries WHERE ts < ?", cutoff)
	return err
}

// HostDNSCount is a per-host DNS query count over a scan window.
type HostDNSCount struct {
	HostID int64
	Count  int
}

// DNSQueryCounts returns per-host DNS query counts in [since, now], used by
// the volume half of the DNS anomaly detector.
func (db *DB) DNSQueryCounts(since, now int64) ([]HostDNSCount, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, COUNT(*) FROM dns_queries WHERE ts >= ? AND ts <= ? GROUP BY host_id`,
		since, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HostDNSCount
	for rows.Next() {
		var c HostDNSCount
		if err := rows.Scan(&c.HostID, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DNSQueryRow is one raw query in a scan window, used by the entropy half of
// the DNS anomaly detector.
type DNSQueryRow struct {
	HostID int64
	QName  string
	TS     int64
}

// DNSQueriesInRange returns every DNS query observed in [since, now].
func (db *DB) DNSQueriesInRange(since, now int64) ([]DNSQueryRow, error) {
	rows, err := db.Reader.Query(
		`SELECT host_id, qname, ts FROM dns_queries WHERE ts >= ? AND ts <= ?`,
		since, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DNSQueryRow
	for rows.Next() {
		var r DNSQueryRow
		if err := rows.Scan(&r.HostID, &r.QName, &r.TS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
