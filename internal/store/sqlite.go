package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	_ "modernc.org/sqlite"
	"nullpaste/internal/model"
)

type SQLite struct {
	db *sql.DB
}

func New(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &SQLite{db: db}
	if err := s.migrate(); err != nil {
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
	s.db.Exec(`ALTER TABLE pastes ADD COLUMN burned BOOLEAN NOT NULL DEFAULT 0`)
	return nil
}

func (s *SQLite) Create(p *model.Paste) (string, error) {
	token, err := generateToken(32)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(token)
	deleteHash := base64.RawURLEncoding.EncodeToString(hash[:])

	_, err = s.db.Exec(
		`INSERT INTO pastes (id, blob, created_at, expires_at, burn, has_duress, delete_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Blob, p.CreatedAt, p.ExpiresAt, p.Burn, p.HasDuress, deleteHash,
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

func (s *SQLite) MarkBurned(id string) error {
	_, err := s.db.Exec(`UPDATE pastes SET burned=1 WHERE id=?`, id)
	return err
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
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func (s *SQLite) DeleteTokenValid(id, token string) bool {
	var deleteHash string
	row := s.db.QueryRow(`SELECT delete_hash FROM pastes WHERE id = ?`, id)
	if err := row.Scan(&deleteHash); err != nil {
		return false
	}
	h := sha256.Sum256([]byte(token))
	given := base64.RawURLEncoding.EncodeToString(h[:])
	return given == deleteHash
}

func generateToken(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
