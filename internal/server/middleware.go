package server

import (
	"log"
	"net/http"
	"strings"
)

func noIPMiddleware(next http.Handler, w http.ResponseWriter, r *http.Request) {
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-IP")
	r.Header.Del("CF-Connecting-IP")

	if ua := r.Header.Get("User-Agent"); strings.Contains(ua, "curl") || strings.Contains(ua, "Wget") {
		log.Printf("[INFO] request: method=%s path=%s ua=%s", r.Method, r.URL.Path, ua)
	}

	next.ServeHTTP(w, r)
}
