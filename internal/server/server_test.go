package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nullpaste/internal/config"
	"nullpaste/internal/model"
	"nullpaste/internal/store"
)

func newTestServer(t *testing.T, mutate func(*config.Config)) *Server {
	t.Helper()
	db, err := store.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		MaxBytes:   1024,
		DefaultTTL: 7 * 24 * time.Hour,
		GCInterval: time.Hour,
	}
	if mutate != nil {
		mutate(cfg)
	}
	srv := New(cfg, db)
	t.Cleanup(func() {
		srv.Shutdown()
		_ = db.Close()
	})
	return srv
}

func do(srv http.Handler, method, target string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func createBody(blob []byte, extra map[string]any) io.Reader {
	m := map[string]any{"blob": base64.StdEncoding.EncodeToString(blob)}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return bytes.NewReader(b)
}

func create(t *testing.T, srv http.Handler, blob []byte, extra map[string]any) model.CreateResponse {
	t.Helper()
	rec := do(srv, http.MethodPost, "/api/paste", createBody(blob, extra))
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body)
	}
	var resp model.CreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestCreateReadDeleteFlow(t *testing.T) {
	srv := newTestServer(t, nil)
	created := create(t, srv, []byte("secret-ciphertext"), map[string]any{"ttl": "1h"})
	if created.ID == "" || created.DeleteToken == "" || created.URL != "/p/"+created.ID {
		t.Fatalf("unexpected create response: %+v", created)
	}

	rec := do(srv, http.MethodGet, "/api/paste/"+created.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("read status = %d", rec.Code)
	}
	var read model.ReadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	got, _ := base64.StdEncoding.DecodeString(read.Blob)
	if string(got) != "secret-ciphertext" || read.Burn || read.ExpiresAt == "" {
		t.Errorf("unexpected read response: %+v", read)
	}

	if rec := do(srv, http.MethodDelete, "/api/paste/"+created.ID+"?token=wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("delete with bad token = %d, want 401", rec.Code)
	}
	if rec := do(srv, http.MethodDelete, "/api/paste/"+created.ID, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("delete without token = %d, want 401", rec.Code)
	}
	if rec := do(srv, http.MethodDelete, "/api/paste/"+created.ID+"?token="+created.DeleteToken, nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete with token = %d, want 204", rec.Code)
	}
	if rec := do(srv, http.MethodGet, "/api/paste/"+created.ID, nil); rec.Code != http.StatusNotFound {
		t.Errorf("read after delete = %d, want 404", rec.Code)
	}
}

func TestReadMissingIs404(t *testing.T) {
	srv := newTestServer(t, nil)
	if rec := do(srv, http.MethodGet, "/api/paste/doesnotexist", nil); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestBurnAfterReadSequential(t *testing.T) {
	srv := newTestServer(t, nil)
	c := create(t, srv, []byte("once"), map[string]any{"burn": true})
	first := do(srv, http.MethodGet, "/api/paste/"+c.ID, nil)
	if first.Code != http.StatusOK || first.Header().Get("X-Burned") != "1" {
		t.Fatalf("first read = %d, X-Burned=%q", first.Code, first.Header().Get("X-Burned"))
	}
	if second := do(srv, http.MethodGet, "/api/paste/"+c.ID, nil); second.Code != http.StatusGone {
		t.Errorf("second read = %d, want 410", second.Code)
	}
}

func TestBurnAfterReadConcurrent(t *testing.T) {
	srv := newTestServer(t, nil)
	c := create(t, srv, []byte("once"), map[string]any{"burn": true})

	const readers = 32
	codes := make([]int, readers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = do(srv, http.MethodGet, "/api/paste/"+c.ID, nil).Code
		}()
	}
	close(start)
	wg.Wait()

	var ok, gone int
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusGone:
			gone++
		default:
			t.Errorf("unexpected status %d", code)
		}
	}
	if ok != 1 || gone != readers-1 {
		t.Errorf("ok=%d gone=%d, want 1 and %d", ok, gone, readers-1)
	}
}

func TestCreateValidation(t *testing.T) {
	srv := newTestServer(t, nil)
	overLimit := base64.StdEncoding.EncodeToString(make([]byte, 1025))
	tests := []struct {
		name string
		body string
		want int
	}{
		{"malformed json", "{", http.StatusBadRequest},
		{"empty blob", `{"blob":""}`, http.StatusBadRequest},
		{"bad base64", `{"blob":"***"}`, http.StatusBadRequest},
		{"bad ttl", `{"blob":"AAAA","ttl":"soon"}`, http.StatusBadRequest},
		{"negative ttl", `{"blob":"AAAA","ttl":"-1h"}`, http.StatusBadRequest},
		{"overflowing ttl", `{"blob":"AAAA","ttl":"99999999999999d"}`, http.StatusBadRequest},
		{"decoded blob over limit", `{"blob":"` + overLimit + `"}`, http.StatusRequestEntityTooLarge},
		{"ok", `{"blob":"AAAA"}`, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(srv, http.MethodPost, "/api/paste", strings.NewReader(tc.body))
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

func TestCreateRejectsOversizedChunkedBody(t *testing.T) {
	srv := newTestServer(t, nil)
	huge := `{"blob":"` + strings.Repeat("A", 1<<20) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/paste", strings.NewReader(huge))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestDefaultTTLApplied(t *testing.T) {
	srv := newTestServer(t, func(c *config.Config) { c.DefaultTTL = time.Hour })
	c := create(t, srv, []byte("x"), nil)
	rec := do(srv, http.MethodGet, "/api/paste/"+c.ID, nil)
	var read model.ReadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	exp, err := time.Parse(time.RFC3339, read.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q: %v", read.ExpiresAt, err)
	}
	if d := time.Until(exp); d < 55*time.Minute || d > time.Hour+time.Minute {
		t.Errorf("expiry in %v, want about 1h", d)
	}
}

func TestNeverTTLHasNoExpiryAndSurvivesSweep(t *testing.T) {
	srv := newTestServer(t, nil)
	c := create(t, srv, []byte("x"), map[string]any{"ttl": "never"})
	if _, err := srv.store.Sweep(time.Now().Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	rec := do(srv, http.MethodGet, "/api/paste/"+c.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var read model.ReadResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &read)
	if read.ExpiresAt != "" {
		t.Errorf("expires_at = %q, want empty", read.ExpiresAt)
	}
}

func TestExpiredPasteIs404(t *testing.T) {
	srv := newTestServer(t, nil)
	c := create(t, srv, []byte("x"), map[string]any{"ttl": "1h"})
	if _, err := srv.store.Sweep(time.Now().Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rec := do(srv, http.MethodGet, "/api/paste/"+c.ID, nil); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := newTestServer(t, nil)
	for _, path := range []string{"/", "/static/index.html", "/p/abc", "/api/paste/none"} {
		rec := do(srv, http.MethodGet, path, nil)
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self';") {
			t.Errorf("%s: weak or missing CSP %q", path, csp)
		}
		for h, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "no-referrer",
			"X-Frame-Options":        "DENY",
		} {
			if got := rec.Header().Get(h); got != want {
				t.Errorf("%s: %s = %q, want %q", path, h, got, want)
			}
		}
	}
	if got := do(srv, http.MethodGet, "/api/paste/none", nil).Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("API Cache-Control = %q, want no-store", got)
	}
}

func TestStaticServing(t *testing.T) {
	srv := newTestServer(t, nil)
	tests := []struct {
		path     string
		want     int
		wantType string
	}{
		{"/static/index.html", http.StatusOK, "text/html; charset=utf-8"},
		{"/static/app.js", http.StatusOK, "application/javascript; charset=utf-8"},
		{"/static/styles.css", http.StatusOK, "text/css; charset=utf-8"},
		{"/p/anything", http.StatusOK, "text/html; charset=utf-8"},
		{"/static/missing.js", http.StatusNotFound, ""},
		{"/static/", http.StatusNotFound, ""},
		// mux cleans the path and redirects
		{"/static/../go.mod", http.StatusTemporaryRedirect, ""},
		{"/no-such-route", http.StatusNotFound, ""},
	}
	for _, tc := range tests {
		rec := do(srv, http.MethodGet, tc.path, nil)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.path, rec.Code, tc.want)
			continue
		}
		if tc.wantType != "" && rec.Header().Get("Content-Type") != tc.wantType {
			t.Errorf("%s: Content-Type = %q, want %q", tc.path, rec.Header().Get("Content-Type"), tc.wantType)
		}
	}
	rec := do(srv, http.MethodGet, "/", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/static/index.html" {
		t.Errorf("/ = %d -> %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestProxyHeadersStripped(t *testing.T) {
	srv := newTestServer(t, nil)
	var seen http.Header
	srv.mux.HandleFunc("GET /_probe", func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() })
	headers := []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"}
	req := httptest.NewRequest(http.MethodGet, "/_probe", nil)
	for _, h := range headers {
		req.Header.Set(h, "203.0.113.9")
	}
	srv.ServeHTTP(httptest.NewRecorder(), req)
	for _, h := range headers {
		if seen.Get(h) != "" {
			t.Errorf("%s reached the handler", h)
		}
	}
}

func TestParseTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const def = 7 * 24 * time.Hour
	tests := []struct {
		ttl      string
		fallback time.Duration
		want     time.Time
		ok       bool
	}{
		{"", def, now.Add(def), true},
		{"", 0, time.Time{}, true},
		{"never", def, time.Time{}, true},
		{"5m", def, now.Add(5 * time.Minute), true},
		{"1h", def, now.Add(time.Hour), true},
		{"1d", def, now.Add(24 * time.Hour), true},
		{"30d", def, now.Add(30 * 24 * time.Hour), true},
		{"0d", def, time.Time{}, false},
		{"-1d", def, time.Time{}, false},
		{"0s", def, time.Time{}, false},
		{"3651d", def, time.Time{}, false},
		{"d", def, time.Time{}, false},
		{"abc", def, time.Time{}, false},
	}
	for _, tc := range tests {
		got, ok := parseTTL(tc.ttl, tc.fallback, now)
		if ok != tc.ok || !got.Equal(tc.want) {
			t.Errorf("parseTTL(%q, %v) = %v, %v; want %v, %v", tc.ttl, tc.fallback, got, ok, tc.want, tc.ok)
		}
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	srv := newTestServer(t, nil)
	srv.Shutdown()
	srv.Shutdown()
}
