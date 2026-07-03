package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"nullpaste/internal/config"
	"nullpaste/internal/gc"
	"nullpaste/internal/model"
	"nullpaste/internal/store"
	"nullpaste/web"
)

type Server struct {
	mux   *http.ServeMux
	store store.Store
	cfg   *config.Config
	gcDone chan struct{}
}

func New(cfg *config.Config, s store.Store) *Server {
	srv := &Server{
		mux:   http.NewServeMux(),
		store: s,
		cfg:   cfg,
		gcDone: make(chan struct{}),
	}
	srv.routes()
	go gc.Start(s, cfg.GCInterval, srv.gcDone)
	return srv
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.serveIndex)
	s.mux.HandleFunc("GET /p/{id}", s.serveView)
	s.mux.HandleFunc("POST /api/paste", s.handleCreate)
	s.mux.HandleFunc("GET /api/paste/{id}", s.handleRead)
	s.mux.HandleFunc("DELETE /api/paste/{id}", s.handleDelete)
	s.mux.HandleFunc("GET /static/", s.serveStatic)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-IP")
	r.Header.Del("CF-Connecting-IP")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Shutdown() {
	close(s.gcDone)
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/static/index.html", http.StatusFound)
}

func (s *Server) serveView(w http.ResponseWriter, r *http.Request) {
	content, err := web.StaticFiles.ReadFile("static/view.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
	w.Write(content)
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/static/" || path == "/static" {
		http.NotFound(w, r)
		return
	}
	filePath := path[len("/static"):]
	if filePath[0] == '/' {
		filePath = filePath[1:]
	}
	content, err := web.StaticFiles.ReadFile("static/" + filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctype := mimeType(filePath)
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
	w.Write(content)
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > s.cfg.MaxBytes {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req model.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	expiresAt, ok := parseTTL(req.TTL, s.cfg.DefaultTTL)
	if !ok {
		http.Error(w, "invalid ttl", http.StatusBadRequest)
		return
	}
	id, err := generateID(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	paste := &model.Paste{
		ID:        id,
		Blob:      blob,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Burn:      req.Burn,
		HasDuress: req.HasDuress,
	}
	deleteToken, err := s.store.Create(paste)
	if err != nil {
		log.Printf("create error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := model.CreateResponse{
		ID:          paste.ID,
		URL:         fmt.Sprintf("/p/%s", paste.ID),
		DeleteToken: deleteToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
	if !paste.ExpiresAt.IsZero() && time.Now().After(paste.ExpiresAt) {
		s.store.Delete(id)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	resp := model.ReadResponse{
		Blob:      base64.StdEncoding.EncodeToString(paste.Blob),
		ExpiresAt: paste.ExpiresAt.Format(time.RFC3339),
		Burn:      paste.Burn,
	}
	if paste.Burn {
		s.store.Delete(id)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

func generateID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func parseTTL(ttl string, fallback time.Duration) (time.Time, bool) {
	if ttl == "" || ttl == "never" {
		return time.Time{}, true
	}
	var d time.Duration
	var err error
	if len(ttl) > 0 && ttl[len(ttl)-1] == 'd' {
		n := ttl[:len(ttl)-1]
		var days int
		days, err = strconv.Atoi(n)
		if err == nil {
			d = time.Duration(days) * 24 * time.Hour
		}
	} else {
		d, err = time.ParseDuration(ttl)
	}
	if err != nil || d <= 0 {
		return time.Time{}, false
	}
	return time.Now().UTC().Add(d), true
}

func mimeType(path string) string {
	switch {
	case stringsHasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case stringsHasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case stringsHasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case stringsHasSuffix(path, ".svg"):
		return "image/svg+xml"
	case stringsHasSuffix(path, ".ico"):
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
