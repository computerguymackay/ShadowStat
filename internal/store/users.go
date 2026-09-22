package store

import (
	"database/sql"
	"errors"
)

// ErrNotFound is returned by lookups that find no matching row.
var ErrNotFound = errors.New("store: not found")

// User is a ShadowStat admin account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    int64
}

// CreateUser inserts a new user with an already-hashed password.
func (db *DB) CreateUser(username, passwordHash string, createdAt int64) (int64, error) {
	res, err := db.Writer.Exec(
		"INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
		username, passwordHash, createdAt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UserByUsername looks up a user by username.
func (db *DB) UserByUsername(username string) (*User, error) {
	var u User
	err := db.Reader.QueryRow(
		"SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// PasswordHashByUserID returns the stored password hash for a user id.
func (db *DB) PasswordHashByUserID(id int64) (string, error) {
	var hash string
	err := db.Reader.QueryRow("SELECT password_hash FROM users WHERE id = ?", id).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return hash, err
}

// AnyUserExists reports whether at least one user account exists.
func (db *DB) AnyUserExists() (bool, error) {
	var count int
	if err := db.Reader.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
