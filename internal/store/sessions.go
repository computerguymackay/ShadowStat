package store

import "database/sql"

// Session is a web login session.
type Session struct {
	Token         string
	UserID        int64
	CreatedAt     int64
	ExpiresAt     int64
	ElevatedUntil sql.NullInt64
}

// CreateSession inserts a new session row.
func (db *DB) CreateSession(token string, userID, createdAt, expiresAt int64) error {
	_, err := db.Writer.Exec(
		"INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		token, userID, createdAt, expiresAt,
	)
	return err
}

// SessionByToken looks up a session by its token.
func (db *DB) SessionByToken(token string) (*Session, error) {
	var s Session
	err := db.Reader.QueryRow(
		"SELECT token, user_id, created_at, expires_at, elevated_until FROM sessions WHERE token = ?",
		token,
	).Scan(&s.Token, &s.UserID, &s.CreatedAt, &s.ExpiresAt, &s.ElevatedUntil)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ElevateSession sets elevated_until on a session, used after a settings re-auth.
func (db *DB) ElevateSession(token string, elevatedUntil int64) error {
	_, err := db.Writer.Exec("UPDATE sessions SET elevated_until = ? WHERE token = ?", elevatedUntil, token)
	return err
}

// DeleteSession removes a session (logout).
func (db *DB) DeleteSession(token string) error {
	_, err := db.Writer.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

// PruneExpiredSessions deletes sessions past their expiry.
func (db *DB) PruneExpiredSessions(now int64) error {
	_, err := db.Writer.Exec("DELETE FROM sessions WHERE expires_at < ?", now)
	return err
}
