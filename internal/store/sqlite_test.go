package store

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nullpaste/internal/model"
)

func newStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newPaste(id string, burn bool, expires time.Time) *model.Paste {
	return &model.Paste{
		ID:        id,
		Blob:      []byte("ciphertext-" + id),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expires,
		Burn:      burn,
	}
}

func TestPragmasApplied(t *testing.T) {
	s := newStore(t)
	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
	var timeout int
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", timeout)
	}
}

func TestCreateGetRoundTrip(t *testing.T) {
	s := newStore(t)
	exp := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	p := newPaste("a", false, exp)
	if _, err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("a")
	if err != nil || got == nil {
		t.Fatalf("Get = %v, %v", got, err)
	}
	if string(got.Blob) != "ciphertext-a" || !got.ExpiresAt.Equal(exp) {
		t.Errorf("unexpected paste: %+v", got)
	}
}

func TestGetMissingReturnsNil(t *testing.T) {
	s := newStore(t)
	got, err := s.Get("nope")
	if err != nil || got != nil {
		t.Fatalf("Get = %v, %v; want nil, nil", got, err)
	}
}

func TestZeroExpiryStoredAsNever(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create(newPaste("n", false, time.Time{})); err != nil {
		t.Fatal(err)
	}
	n, err := s.Sweep(time.Now().Add(100 * 365 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("Sweep removed %d never-expiring pastes", n)
	}
}

func TestDeleteTokenValid(t *testing.T) {
	s := newStore(t)
	tok, err := s.Create(newPaste("d", false, time.Time{}))
	if err != nil {
		t.Fatal(err)
	}
	if !s.DeleteTokenValid("d", tok) {
		t.Error("valid token rejected")
	}
	for name, bad := range map[string]string{
		"wrong":     "AAAA",
		"not-b64":   "!!!",
		"empty":     "",
		"truncated": tok[:len(tok)-2],
	} {
		if s.DeleteTokenValid("d", bad) {
			t.Errorf("%s token accepted", name)
		}
	}
	if s.DeleteTokenValid("other", tok) {
		t.Error("token accepted for a different paste id")
	}
}

func TestSweepRemovesOnlyExpired(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()
	for id, exp := range map[string]time.Time{
		"old":   now.Add(-time.Minute),
		"fresh": now.Add(time.Hour),
		"never": {},
	} {
		if _, err := s.Create(newPaste(id, false, exp)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.Sweep(now)
	if err != nil || n != 1 {
		t.Fatalf("Sweep = %d, %v; want 1, nil", n, err)
	}
	if p, _ := s.Get("old"); p != nil {
		t.Error("expired paste survived sweep")
	}
	for _, id := range []string{"fresh", "never"} {
		if p, _ := s.Get(id); p == nil {
			t.Errorf("%s was swept", id)
		}
	}
}

func TestBurnIsAtomicUnderConcurrency(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create(newPaste("b", true, time.Time{})); err != nil {
		t.Fatal(err)
	}
	const workers = 64
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			won, err := s.Burn("b")
			if err != nil {
				t.Errorf("Burn: %v", err)
				return
			}
			if won {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("%d callers won the burn, want exactly 1", got)
	}
}

func TestBurnDiscardsCiphertext(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create(newPaste("b", true, time.Time{})); err != nil {
		t.Fatal(err)
	}
	if won, err := s.Burn("b"); err != nil || !won {
		t.Fatalf("Burn = %v, %v", won, err)
	}
	p, err := s.Get("b")
	if err != nil || p == nil {
		t.Fatalf("Get = %v, %v", p, err)
	}
	if !p.Burned || len(p.Blob) != 0 {
		t.Errorf("burned=%v blob=%q; want burned with empty blob", p.Burned, p.Blob)
	}
	if won, _ := s.Burn("b"); won {
		t.Error("second Burn succeeded")
	}
}

func TestBurnIgnoresNonBurnPastes(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create(newPaste("p", false, time.Time{})); err != nil {
		t.Fatal(err)
	}
	if won, err := s.Burn("p"); err != nil || won {
		t.Fatalf("Burn on non-burn paste = %v, %v; want false, nil", won, err)
	}
	if p, _ := s.Get("p"); p == nil || len(p.Blob) == 0 {
		t.Error("non-burn paste was damaged")
	}
}

func TestSweepClearsLeftoverBurnedBlobs(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create(newPaste("b", true, time.Time{})); err != nil {
		t.Fatal(err)
	}
	// crash between claim and wipe
	if _, err := s.db.Exec(`UPDATE pastes SET burned = 1 WHERE id = 'b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sweep(time.Now()); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Get("b")
	if p == nil || len(p.Blob) != 0 {
		t.Errorf("blob not cleared by sweep: %+v", p)
	}
}

func TestReopenKeepsDataAndMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "re.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(newPaste("k", false, time.Time{})); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = New(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s.Close() }()
	if p, _ := s.Get("k"); p == nil {
		t.Error("data lost across reopen")
	}
}
