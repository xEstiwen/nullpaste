# Changelog

## 0.2.0 - 2026-11-27

### Fixed
- Pastes created with `ttl=never` were deleted by the first GC sweep.
- Burn-after-read could reveal a paste to several concurrent readers.
- Burned pastes kept their ciphertext in the database.
- `NULLPASTE_DEFAULT_TTL` was ignored; an empty `ttl` now uses it, as documented in the API docs.
- The Docker image exited on start because `--addr` and `--db-path` were not defined.
- SQLite WAL and busy timeout were never applied (wrong DSN syntax for the driver).
- Request bodies were not bounded for chunked uploads.
- Day-based TTLs could overflow into the past.
- `LICENSE` held only part of the AGPL-3.0 text.

### Changed
- Real command line flags: `--addr`, `--db-path`, `--version`.
- HTTP server timeouts and graceful shutdown (the database is now closed on exit).
- CSP no longer allows inline scripts. Added `Referrer-Policy`, `X-Frame-Options` and `Cache-Control: no-store` on the API.
- Unknown routes return 404 instead of redirecting to the index page.
- Delete tokens are compared in constant time.
- Docker image is built from source in a multi-stage build and runs as non-root.
- Go toolchain 1.26.11 (fixes stdlib advisories reported by govulncheck).

### Added
- Unit and HTTP tests for every package, race detector in CI.
- CI: tidy check, lint, govulncheck, Docker smoke test, Linux/macOS/Windows test matrix.
