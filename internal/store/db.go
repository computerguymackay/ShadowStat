// Package store owns all database/sql access for ShadowStat's SQLite database.
package store

import (
	"database/sql"
	"embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

const schemaVersion = 1

// DB holds the writer and reader connections for the ShadowStat database.
// Writer is limited to a single open connection so all writes are serialized
// through database/sql's pool; Reader allows a small pool of concurrent readers.
// Both point at the same WAL-mode file, so readers never block on the writer.
type DB struct {
	Writer *sql.DB
	Reader *sql.DB
	path   string
}

// Open opens (or creates) the SQLite database at path and configures WAL mode.
// Callers should check whether path exists via os.Stat *before* calling Open
// if they need to distinguish "first run" from "existing database".
func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path)

	writer, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open writer: %w", err)
	}
	writer.SetMaxOpenConns(1)

	reader, err := sql.Open("sqlite", dsn)
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("open reader: %w", err)
	}
	reader.SetMaxOpenConns(4)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA auto_vacuum=INCREMENTAL",
	} {
		if _, err := writer.Exec(pragma); err != nil {
			writer.Close()
			reader.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	if _, err := reader.Exec("PRAGMA foreign_keys=ON"); err != nil {
		writer.Close()
		reader.Close()
		return nil, fmt.Errorf("reader pragma: %w", err)
	}

	db := &DB{Writer: writer, Reader: reader, path: path}
	if err := db.migrate(); err != nil {
		writer.Close()
		reader.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// Close closes both the writer and reader connections.
func (db *DB) Close() error {
	werr := db.Writer.Close()
	rerr := db.Reader.Close()
	if werr != nil {
		return werr
	}
	return rerr
}

func (db *DB) migrate() error {
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	if _, err := db.Writer.Exec(string(schema)); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}

	// schema.sql only CREATEs tables that don't yet exist, so a column added
	// to an existing table's definition here needs an explicit ALTER for
	// databases created before that column existed.
	if err := db.ensureColumn("hosts", "mac_address", "TEXT"); err != nil {
		return fmt.Errorf("migrate hosts.mac_address: %w", err)
	}

	var count int
	if err := db.Writer.QueryRow("SELECT COUNT(*) FROM schema_meta").Scan(&count); err != nil {
		return fmt.Errorf("check schema_meta: %w", err)
	}
	if count == 0 {
		if _, err := db.Writer.Exec("INSERT INTO schema_meta (version) VALUES (?)", schemaVersion); err != nil {
			return fmt.Errorf("insert schema_meta: %w", err)
		}
	}
	return nil
}

// ensureColumn adds column to table (with the given SQLite type) if it
// doesn't already exist. SQLite has no "ADD COLUMN IF NOT EXISTS", so
// existence is checked via PRAGMA table_info first.
func (db *DB) ensureColumn(table, column, sqlType string) error {
	rows, err := db.Writer.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil // already present
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = db.Writer.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, sqlType))
	return err
}
