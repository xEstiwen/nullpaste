# Nullpaste

[![CI](https://github.com/xEstiwen/nullpaste/actions/workflows/ci.yml/badge.svg)](https://github.com/xEstiwen/nullpaste/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

> Zero-knowledge pastebin with plausible deniability built in.

Content is encrypted in your browser using AES-GCM before it ever touches the server. The server stores encrypted blobs and metadata (timestamps, burn flags) — it **cannot read the actual content**, it **never sees encryption keys or passwords**, and it has **no way to decrypt** what it stores. A unique **duress password** feature provides deniable encryption: enter one password to reveal the real paste, another to reveal a decoy. To a server or network observer, both look identical.

## Features

- **Zero-knowledge architecture** — encryption/decryption happens entirely in the browser via Web Crypto API. The server stores only encrypted blobs, never plaintext.
- **Duress / deniable encryption** — optionally set a second password and separate decoy content. The server cannot distinguish which password was used or which content is "real".
- **Burn after read** — the first successful read claims the paste atomically and the server discards the ciphertext. Concurrent readers get `410 Gone`.
- **TTL auto-expiry** — choose from 5 minutes, 1 hour, 1 day, 7 days, 30 days, or never.
- **Privacy-first** — no IP logging, no User-Agent storage, no analytics.
- **Export ciphertext** — encrypt offline and share the ciphertext directly, no server required.
- **Single binary** — one executable, SQLite embedded, zero external dependencies.
- **Self-hostable** — runs on Linux, macOS, Windows. Docker and systemd unit included.

## What the server stores

| Data | Stored? | Notes |
|---|---|---|
| Encrypted content (AES-GCM 256-bit) | Yes | Opaque blob, server cannot read |
| Paste ID (128-bit random) | Yes | Public by design, needed for link |
| Creation & expiry timestamps | Yes | Metadata for TTL auto-delete |
| Burn-after-read flag | Yes | Boolean, paste is marked burned after first read |
| Burned status | Yes | Returns 410 Gone on subsequent reads; the ciphertext itself is wiped |
| Delete token (SHA-256 hash) | Yes | Hash of raw token bytes, not reversible |
| **IP address** | **No** | Stripped at handler level |
| **User-Agent** | **No** | Not logged or stored |
| **Password** | **No** | Never transmitted to server |
| **Encryption key** | **No** | Never leaves the browser (URL fragment) |
| **Plaintext content** | **No** | Encrypted before upload |

## Quick Start

### Pre-built Binary

Download from [Releases](https://github.com/xEstiwen/nullpaste/releases) or build from source.

```bash
# Run
./nullpaste --addr :8080 --db-path nullpaste.db

# Print the version
./nullpaste --version

# Open in browser
open http://localhost:8080
```

### Docker

Build and run:

```bash
docker build -t nullpaste .
docker run -d --name nullpaste \
  -p 8080:8080 \
  -v nullpaste-data:/data \
  nullpaste
```

Or with `docker-compose`:

```bash
docker compose up -d
```

### Build from Source

```bash
git clone https://github.com/xEstiwen/nullpaste.git
cd nullpaste
go build -o nullpaste ./cmd/nullpaste
./nullpaste
```

![Nullpaste screenshot](docs/image.png)

## Configuration

Flags: `--addr`, `--db-path`, `--version`. Everything else is set through environment variables, which also provide the defaults for the flags:

| Variable | Default | Description |
|---|---|---|
| `NULLPASTE_ADDR` | `:8080` | Listen address |
| `NULLPASTE_DB_PATH` | `nullpaste.db` | SQLite database path |
| `NULLPASTE_MAXBYTES` | `262144` | Max paste size in bytes (256 KiB default) |
| `NULLPASTE_DEFAULT_TTL` | `168h` | TTL used when a request does not send one (7 days) |
| `NULLPASTE_GC_INTERVAL` | `1h` | Garbage collection interval |

## How It Works

### Link-only Mode (No Password)

```
[Browser]                         [Server]
   |                                  |
   |-- generate random 256-bit key --|
   |-- encrypt content (AES-GCM) ---->|
   |-- POST encrypted blob --------->|
   |<-- { id, url } ----------------|
   |-- serve /p/id#k=base64(key) ----|
```

The key lives in the URL fragment (`#k=...`). HTTP servers never see URL fragments, so the key never touches the network. The view page is served at `/p/:id`, preserving the fragment in the browser.

### Password + Duress Mode

```
[Creator Browser]
  |-- derive K_real from real password
  |-- derive K_duress from duress password
  |-- generate content_key_real, encrypt content
  |-- generate content_key_duress, encrypt decoy
  |-- wrap content_key_real with K_real
  |-- wrap content_key_duress with K_duress
  |-- POST blob (two ciphertexts + two wrapped keys) to server
  |-- server stores opaque blob
  |-- share /p/id#p=1 + tell recipient password
```

```
[Reader Browser — real password]
  |-- derive K from real password
  |-- unwrap content_key_real
  |-- decrypt real content
```

```
[Reader Browser — duress password]
  |-- derive K from duress password
  |-- unwrap content_key_duress
  |-- decrypt decoy content
```

Note: the same container format and duress support apply to **Export Ciphertext mode** (serverless). The entire encryption/decryption happens in the browser, no server required. See [docs/CRYPTO.md](docs/CRYPTO.md) for the full cryptographic design.

## Tech Stack

| Layer | Choice |
|---|---|
| Backend | Go (single static binary) |
| Database | SQLite (embedded via `modernc.org/sqlite`) |
| Frontend | Vanilla JS + Web Crypto API (no build step) |
| Assets | Embedded in binary via `go:embed` |

## API

### Create Paste

```
POST /api/paste
Content-Type: application/json

{
  "blob": "base64-encoded encrypted container",
  "ttl": "7d",
  "burn": false,
  "has_duress": false
}

Response 200:
{
  "id": "paste_id",
  "url": "/p/paste_id",
  "delete_token": "opaque_token"
}
```

### Read Paste

```
GET /api/paste/:id

Response 200:
{
  "blob": "base64-encoded encrypted container",
  "expires_at": "2026-07-09T00:00:00Z",
  "burn": false
}
```

### Delete Paste

```
DELETE /api/paste/:id?token=<delete_token>

Response 204: No Content
```

## Security Notes

- **Offline brute-force:** Because decryption is client-side, anyone who obtains the encrypted blob can attempt offline brute-force. Defense: choose a strong password. 600,000 PBKDF2 iterations slow down attacks significantly.
- **Duress password strength:** Your duress password should be as strong as your real password. An attacker who reads the open-source client code can identify the two ciphertexts, but cannot prove which is real without the passwords.
- **Burn-after-read:** The paste is returned on the first GET, then marked as `burned`. A second GET returns 410 Gone. A failed decryption attempt (wrong key) still burns the paste — this is a deliberate trade-off for server-side simplicity.
- **Request limits:** the body is capped at the base64 size of `NULLPASTE_MAXBYTES` plus a small envelope, including chunked uploads. The server has read/write/idle timeouts and shuts down gracefully on SIGINT/SIGTERM.
- **Browser hardening:** the CSP forbids inline and third-party scripts, and responses carry `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and (for the API) `Cache-Control: no-store`.
- **No IP logging:** `X-Forwarded-For`, `X-Real-IP`, and `CF-Connecting-IP` headers are stripped from all requests.

## Development

```bash
go test ./...            # unit and HTTP tests
go test -race ./...      # needs cgo
golangci-lint run
```

CI runs the same checks plus `govulncheck`, a `go mod tidy` diff check and a Docker smoke test. See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md). Vulnerability reports: [SECURITY.md](SECURITY.md).

## Architecture

```mermaid
graph TD
    A["Browser<br/>(Encrypt)"] -->|POST /api/paste| B["Go Server"]
    B --> C["SQLite"]
    B -->|opaque blob| C
    C -->|blob lookup| B
    B -->|blob| A

    V["Visitor"] -->|GET /p/:id#k=key| B
    B -->|serve view.html| V
    V -->|fetch blob| B
    B -->|blob| V
    V -->|"decrypt (AES-GCM)"| V
```

## License

[AGPL-3.0](LICENSE)
