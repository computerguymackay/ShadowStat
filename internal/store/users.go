package store

import (
	"database/sql"
	"errors"
)

// ErrNotFound is returned by lookups that find no matching row.
var ErrNotFound = errors.New("store: not found")

// User roles. Admins can change settings, manage users, toggle detectors,
// and acknowledge alerts; standard users can only view the dashboard/host
// detail/alerts pages — no mutating action is available to them.
const (
	RoleAdmin    = "admin"
	RoleStandard = "standard"
)

// User is a ShadowStat account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	CreatedAt    int64
}

// IsAdmin reports whether u has the admin role.
func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

// CreateUser inserts a new user with an already-hashed password.
func (db *DB) CreateUser(username, passwordHash, role string, createdAt int64) (int64, error) {
	res, err := db.Writer.Exec(
		"INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
		username, passwordHash, role, createdAt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const userColumns = "id, username, password_hash, role, created_at"

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

// UserByUsername looks up a user by username.
func (db *DB) UserByUsername(username string) (*User, error) {
	u, err := scanUser(db.Reader.QueryRow("SELECT "+userColumns+" FROM users WHERE username = ?", username))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

// UserByID looks up a user by id.
func (db *DB) UserByID(id int64) (*User, error) {
	u, err := scanUser(db.Reader.QueryRow("SELECT "+userColumns+" FROM users WHERE id = ?", id))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
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

// ListUsers returns every user account, oldest first.
func (db *DB) ListUsers() ([]User, error) {
	rows, err := db.Reader.Query("SELECT " + userColumns + " FROM users ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// CountAdmins returns how many accounts currently have the admin role, used
// to prevent removing or demoting the last one (which would lock everyone
// out of settings/user management with no way back in through the UI).
func (db *DB) CountAdmins() (int, error) {
	var count int
	err := db.Reader.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", RoleAdmin).Scan(&count)
	return count, err
}

// UpdateUserRole changes a user's role.
func (db *DB) UpdateUserRole(id int64, role string) error {
	_, err := db.Writer.Exec("UPDATE users SET role = ? WHERE id = ?", role, id)
	return err
}

// DeleteUser removes a user account. Any of their sessions are cascaded away
// (sessions.user_id has ON DELETE CASCADE).
func (db *DB) DeleteUser(id int64) error {
	_, err := db.Writer.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}
