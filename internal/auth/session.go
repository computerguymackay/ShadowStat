package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"ShadowStat/internal/store"
)

// SessionIdleTimeout is how long an unused session stays valid.
const SessionIdleTimeout = 24 * time.Hour

// ElevationDuration is how long a re-authenticated ("elevated") session may
// perform settings-mutating actions before needing to re-auth again.
const ElevationDuration = 15 * time.Minute

// Manager issues and validates sessions backed by the store.
type Manager struct {
	db *store.DB
}

func NewManager(db *store.DB) *Manager {
	return &Manager{db: db}
}

// NewToken generates a random 32-byte, base64url-encoded session token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Login verifies credentials and, on success, creates a new session and returns its token.
func (m *Manager) Login(username, password string) (token string, err error) {
	u, err := m.db.UserByUsername(username)
	if err != nil {
		return "", err
	}
	ok, err := VerifyPassword(password, u.PasswordHash)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrInvalidCredentials
	}

	token, err = NewToken()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	expires := time.Now().Add(SessionIdleTimeout).Unix()
	if err := m.db.CreateSession(token, u.ID, now, expires); err != nil {
		return "", err
	}
	return token, nil
}

// Validate returns the session for token if it exists and hasn't expired.
func (m *Manager) Validate(token string) (*store.Session, error) {
	s, err := m.db.SessionByToken(token)
	if err != nil {
		return nil, err
	}
	if s.ExpiresAt < time.Now().Unix() {
		return nil, store.ErrNotFound
	}
	return s, nil
}

// Elevate re-verifies the session's user's password and marks the session elevated,
// required before settings-mutating endpoints will proceed.
func (m *Manager) Elevate(token, password string) error {
	s, err := m.Validate(token)
	if err != nil {
		return err
	}
	ok, err := m.verifyPasswordForUser(s.UserID, password)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}
	return m.db.ElevateSession(s.Token, time.Now().Add(ElevationDuration).Unix())
}

func (m *Manager) verifyPasswordForUser(userID int64, password string) (bool, error) {
	hash, err := m.db.PasswordHashByUserID(userID)
	if err != nil {
		return false, err
	}
	return VerifyPassword(password, hash)
}

// IsElevated reports whether a session currently has settings-change privileges.
func IsElevated(s *store.Session) bool {
	return s.ElevatedUntil.Valid && s.ElevatedUntil.Int64 > time.Now().Unix()
}

// Logout deletes a session.
func (m *Manager) Logout(token string) error {
	return m.db.DeleteSession(token)
}

// ErrInvalidCredentials is returned when a login/elevate attempt fails verification.
var ErrInvalidCredentials = fmt.Errorf("auth: invalid credentials")
