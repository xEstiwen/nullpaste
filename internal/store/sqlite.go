package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"nullpaste/internal/model"
)

type SQLite struct {
	db *sql.DB
}

func New(path string) (*SQLite, error) {
	// modernc ignores mattn-style keys like _journal_mode, it wants _pragma=
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &SQLite{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLite) migrate() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS pastes (
		id          TEXT PRIMARY KEY,
		blob        BLOB NOT NULL,
		created_at  DATETIME NOT NULL,
		expires_at  DATETIME,
		burn        BOOLEAN NOT NULL DEFAULT 0,
		burned      BOOLEAN NOT NULL DEFAULT 0,
		has_duress  BOOLEAN NOT NULL DEFAULT 0,
		delete_hash TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_expires ON pastes(expires_at);
	`)
	if err != nil {
		return err
	}
	// older databases don't have the burned column yet
	if _, err := s.db.Exec(`ALTER TABLE pastes ADD COLUMN burned BOOLEAN NOT NULL DEFAULT 0`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

func (s *SQLite) Create(p *model.Paste) (string, error) {
	token, err := generateToken(32)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(token)
	deleteHash := base64.RawURLEncoding.EncodeToString(hash[:])

	// zero time has to go in as NULL, otherwise Sweep deletes it
	var expiresAt sql.NullTime
	if !p.ExpiresAt.IsZero() {
		expiresAt = sql.NullTime{Time: p.ExpiresAt, Valid: true}
	}
	_, err = s.db.Exec(
		`INSERT INTO pastes (id, blob, created_at, expires_at, burn, has_duress, delete_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Blob, p.CreatedAt, expiresAt, p.Burn, p.HasDuress, deleteHash,
	)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (s *SQLite) Get(id string) (*model.Paste, error) {
	row := s.db.QueryRow(
		`SELECT id, blob, created_at, expires_at, burn, burned, has_duress FROM pastes WHERE id = ?`,
		id,
	)
	var p model.Paste
	var expiresAt sql.NullTime
	err := row.Scan(&p.ID, &p.Blob, &p.CreatedAt, &expiresAt, &p.Burn, &p.Burned, &p.HasDuress)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		p.ExpiresAt = expiresAt.Time
	}
	return &p, nil
}

func (s *SQLite) Burn(id string) (bool, error) {
	// one UPDATE is the claim, only one caller can see RowsAffected == 1
	res, err := s.db.Exec(`UPDATE pastes SET burned = 1 WHERE id = ? AND burn = 1 AND burned = 0`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return false, err
	}
	// best effort, Sweep cleans up if this fails
	_, _ = s.db.Exec(`UPDATE pastes SET blob = x'' WHERE id = ?`, id)
	return true, nil
}

func (s *SQLite) Delete(id string) error {
	_, err := s.db.Exec(`DELETE FROM pastes WHERE id = ?`, id)
	return err
}

func (s *SQLite) Sweep(before time.Time) (int, error) {
	res, err := s.db.Exec(`DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at <= ?`, before)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	// blobs left behind by interrupted burns
	if _, err := s.db.Exec(`UPDATE pastes SET blob = x'' WHERE burned = 1 AND length(blob) > 0`); err != nil {
		return int(n), err
	}
	return int(n), nil
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func (s *SQLite) DeleteTokenValid(id, tokenStr string) bool {
	var deleteHash string
	row := s.db.QueryRow(`SELECT delete_hash FROM pastes WHERE id = ?`, id)
	if err := row.Scan(&deleteHash); err != nil {
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		return false
	}
	h := sha256.Sum256(token)
	given := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(given), []byte(deleteHash)) == 1
}

func generateToken(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
