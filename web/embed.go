package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var StaticFiles embed.FS

var _ fs.FS = StaticFiles

func ServeFile(w http.ResponseWriter, r *http.Request, dir, path string) {
	content, err := StaticFiles.ReadFile(dir + path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctype := mimeType(path)
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
	w.Write(content)
}

func mimeType(path string) string {
	ext := path[strings.LastIndex(path, "."):]
	switch ext {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}
