package store

import "database/sql"

// Session is a web login session. Role is joined fresh from users on every
// lookup (not cached at login time), so a role change takes effect on a
// user's very next request rather than only their next login.
type Session struct {
	Token         string
	UserID        int64
	Role          string
	CreatedAt     int64
	ExpiresAt     int64
	ElevatedUntil sql.NullInt64
}

// IsAdmin reports whether the session's user has the admin role.
func (s *Session) IsAdmin() bool { return s.Role == RoleAdmin }

// CreateSession inserts a new session row.
func (db *DB) CreateSession(token string, userID, createdAt, expiresAt int64) error {
	_, err := db.Writer.Exec(
		"INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		token, userID, createdAt, expiresAt,
	)
	return err
}

// SessionByToken looks up a session by its token, joined with the user's
// current role.
func (db *DB) SessionByToken(token string) (*Session, error) {
	var s Session
	err := db.Reader.QueryRow(
		`SELECT s.token, s.user_id, u.role, s.created_at, s.expires_at, s.elevated_until
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token = ?`,
		token,
	).Scan(&s.Token, &s.UserID, &s.Role, &s.CreatedAt, &s.ExpiresAt, &s.ElevatedUntil)
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
