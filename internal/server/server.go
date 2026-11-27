package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nullpaste/internal/config"
	"nullpaste/internal/gc"
	"nullpaste/internal/model"
	"nullpaste/internal/store"
	"nullpaste/web"
)

// room for the json envelope around the base64 blob
const jsonOverhead = 1024

// no inline scripts; inline styles stay because the pages use style attributes
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

type Server struct {
	mux      *http.ServeMux
	store    store.Store
	cfg      *config.Config
	gcDone   chan struct{}
	stopOnce sync.Once
}

func New(cfg *config.Config, s store.Store) *Server {
	srv := &Server{
		mux:    http.NewServeMux(),
		store:  s,
		cfg:    cfg,
		gcDone: make(chan struct{}),
	}
	srv.routes()
	go gc.Start(s, cfg.GCInterval, srv.gcDone)
	return srv
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /{$}", s.serveIndex)
	s.mux.HandleFunc("GET /p/{id}", s.serveView)
	s.mux.HandleFunc("POST /api/paste", s.handleCreate)
	s.mux.HandleFunc("GET /api/paste/{id}", s.handleRead)
	s.mux.HandleFunc("DELETE /api/paste/{id}", s.handleDelete)
	s.mux.HandleFunc("GET /static/{path...}", s.serveStatic)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-IP")
	r.Header.Del("CF-Connecting-IP")

	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.Set("Cache-Control", "no-store")
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Shutdown() {
	s.stopOnce.Do(func() { close(s.gcDone) })
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/static/index.html", http.StatusFound)
}

func (s *Server) serveView(w http.ResponseWriter, r *http.Request) {
	s.writeStatic(w, r, "view.html")
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	s.writeStatic(w, r, r.PathValue("path"))
}

func (s *Server) writeStatic(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" {
		http.NotFound(w, r)
		return
	}
	content, err := web.StaticFiles.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mimeType(name))
	_, _ = w.Write(content) //nolint:gosec // embedded asset
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	// ContentLength is -1 for chunked bodies, so cap the reader itself
	limit := int64(base64.StdEncoding.EncodedLen(int(s.cfg.MaxBytes))) + jsonOverhead
	r.Body = http.MaxBytesReader(w, r.Body, limit)

	var req model.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Blob)
	if err != nil || len(blob) == 0 {
		http.Error(w, "invalid blob", http.StatusBadRequest)
		return
	}
	if int64(len(blob)) > s.cfg.MaxBytes {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	expiresAt, ok := parseTTL(req.TTL, s.cfg.DefaultTTL, time.Now())
	if !ok {
		http.Error(w, "invalid ttl", http.StatusBadRequest)
		return
	}
	id, err := generateID(16)
	if err != nil {
		log.Printf("id generation error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	paste := &model.Paste{
		ID:        id,
		Blob:      blob,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Burn:      model.ParseBool(req.Burn),
		HasDuress: model.ParseBool(req.HasDuress),
	}
	deleteToken, err := s.store.Create(paste)
	if err != nil {
		log.Printf("create error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, model.CreateResponse{
		ID:          paste.ID,
		URL:         "/p/" + paste.ID,
		DeleteToken: deleteToken,
	})
}

func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	paste, err := s.store.Get(id)
	if err != nil {
		log.Printf("read error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if paste == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if paste.Burned {
		http.Error(w, "this paste was burned", http.StatusGone)
		return
	}
	if !paste.ExpiresAt.IsZero() && time.Now().After(paste.ExpiresAt) {
		if err := s.store.Delete(id); err != nil {
			log.Printf("expired delete error: %v", err)
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if paste.Burn {
		// only the request that wins the claim gets the blob
		won, err := s.store.Burn(id)
		if err != nil {
			log.Printf("burn error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !won {
			http.Error(w, "this paste was burned", http.StatusGone)
			return
		}
		w.Header().Set("X-Burned", "1")
	}
	resp := model.ReadResponse{
		Blob: base64.StdEncoding.EncodeToString(paste.Blob),
		Burn: paste.Burn,
	}
	if !paste.ExpiresAt.IsZero() {
		resp.ExpiresAt = paste.ExpiresAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token := r.URL.Query().Get("token")
	if token == "" || !s.store.DeleteTokenValid(id, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.store.Delete(id); err != nil {
		log.Printf("delete error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func generateID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// zero time means no expiry
func parseTTL(ttl string, fallback time.Duration, now time.Time) (time.Time, bool) {
	switch ttl {
	case "never":
		return time.Time{}, true
	case "":
		if fallback <= 0 {
			return time.Time{}, true
		}
		return now.UTC().Add(fallback), true
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(ttl, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 || n > maxTTLDays {
			return time.Time{}, false
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		d, err = time.ParseDuration(ttl)
		if err != nil || d <= 0 {
			return time.Time{}, false
		}
	}
	return now.UTC().Add(d), true
}

// keeps n*24h from overflowing
const maxTTLDays = 3650

func mimeType(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".ico"):
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}
