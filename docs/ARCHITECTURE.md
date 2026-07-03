# Architecture

## Overview

Nullpaste is a zero-knowledge paste service. The server's only job is to store and retrieve opaque encrypted blobs — it never holds decryption keys and cannot inspect content.

## Components

```
web/              Static assets (HTML, CSS, JS)
  index.html      Create paste UI
  view.html       View/decrypt paste UI
  static/
    app.js        All crypto logic (Web Crypto API)
    styles.css    Dark theme styles

internal/
  config/        Environment-based configuration
  model/         Paste struct, request/response types
  store/         Store interface + SQLite implementation
  gc/            TTL background sweeper
  server/        HTTP server, handlers, middleware
    static/       Static file embedding

cmd/nullpaste/    Entry point
```

## Request Flow

### Create Paste (Link-only)

```
Browser                      Server                       SQLite
  |                            |                            |
  |-- generate 256-bit key --->                             |
  |-- AES-GCM encrypt --------->                             |
  |-- POST /api/paste ---------> INSERT blob --------------->|
  |<-- { id, url } -----------|                             |
  |-- redirect #k=<key> ------>                              |
```

### Create Paste (Password + Duress)

```
Browser
  |
  |-- derive K_real = PBKDF2(pw_real, salt)
  |-- derive K_duress = PBKDF2(pw_duress, salt)
  |-- generate content_key_real
  |-- generate content_key_duress
  |-- encrypt real_content with content_key_real
  |-- encrypt decoy_content with content_key_duress
  |-- wrap content_key_real with K_real (AES-KW)
  |-- wrap content_key_duress with K_duress (AES-KW)
  |
  |-- POST JSON blob (both ciphertexts, both wrapped keys)
  |-- INSERT opaque blob -------------------------------->|
```

### Read Paste (Link-only)

```
Browser                     Server                       SQLite
  |                            |                            |
  |-- GET /p/id#k=key --------->                            |
  |<-- 302 /static/view.html#id                            |
  |-- JS reads key from fragment                            |
  |-- GET /api/paste/:id ----> SELECT blob --------------->|
  |<-- { blob } ---------------|                            |
  |-- AES-GCM decrypt with key                               |
  |-- display content                                       |
```

### Read Paste (Password)

```
Browser                     Server                       SQLite
  |                            |                            |
  |-- GET /p/id#p=1 --------->                             |
  |-- JS shows password prompt                              |
  |-- user enters password                                 |
  |-- derive K = PBKDF2(pw, salt_real)                     |
  |-- unwrap content_key_real (AES-KW)                     |
  |   if tag valid: decrypt C_real -> show real            |
  |   else: derive K2 = PBKDF2(pw, salt_duress)            |
  |   unwrap content_key_duress                             |
  |   decrypt C_duress -> show decoy                        |
```

## Container Format (JSON)

### Link-only

```json
{
  "v": 1,
  "m": 1,
  "c": "<base64 nonce+ciphertext+tag>"
}
```

### Password (with optional duress)

```json
{
  "v": 1,
  "m": 2,
  "s": {
    "r": "<base64 salt for real password>",
    "d": "<base64 salt for duress password or null>"
  },
  "c": {
    "r": "<base64 nonce+ciphertext+tag (real)>",
    "d": "<base64 nonce+ciphertext+tag (decoy) or null>"
  },
  "w": {
    "r": "<base64 wrapped content_key_real>",
    "d": "<base64 wrapped content_key_duress or null>"
  },
  "p": 1
}
```

## Security Boundaries

| Trust boundary | What it sees | What it cannot see |
|---|---|---|
| Network observer | paste id, blob bytes, TTL, burn flag | content, keys, passwords |
| Server process | paste id, blob, expiry, burn flag | content, keys, passwords |
| Client browser | content, keys in memory | nothing server-side |

## Privacy Design

- No IP addresses logged.
- No User-Agent stored.
- `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` stripped at middleware layer.
- IDs are 128-bit random base64url tokens — unguessable.
- Content is AES-GCM authenticated encryption — cannot be tampered with without detection.
