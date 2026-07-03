# API Reference

Base URL: `https://your-nullpaste-instance.com`

All API endpoints return JSON. `Content-Type: application/json` is required for POST bodies.

## Endpoints

### Create Paste

```http
POST /api/paste
```

**Request body:**

```json
{
  "blob": "eyJ2IjoxLCJtIjoxLCJjIjoiLi4uIn0=",
  "ttl": "7d",
  "burn": false,
  "has_duress": false
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `blob` | string | Yes | Base64-encoded encrypted container (see [Container Format](../docs/ARCHITECTURE.md#container-format-json)) |
| `ttl` | string | No | Auto-delete interval. `5m`, `1h`, `1d`, `7d`, `30d`, `never`. Default: `7d` |
| `burn` | bool | No | If `true`, paste is deleted on first read. Default: `false` |
| `has_duress` | bool | No | `true` if a duress password was configured. Default: `false` |

**Response `201 Created`:**

```json
{
  "id": "a3f8b2c1d4e5f678",
  "url": "/p/a3f8b2c1d4e5f678",
  "delete_token": "xK9m..."
}
```

| Field | Type | Description |
|---|---|---|
| `id` | string | Paste ID (128-bit, base64url). Used to construct the URL. |
| `url` | string | Relative URL path for the paste. Append to your instance host. |
| `delete_token` | string | Token required to delete the paste. **Save this.** |

**Share URL for link-only pastes:** `/p/{id}#k={base64(content_key)}`
**Share URL for password pastes:** `/p/{id}#p=1` + share password separately.

---

### Read Paste

```http
GET /api/paste/:id
```

**Response `200 OK`:**

```json
{
  "blob": "eyJ2IjoxLCJtIjoxLCJjIjoiLi4uIn0=",
  "expires_at": "2026-07-09T00:00:00Z",
  "burn": false
}
```

| Field | Type | Description |
|---|---|---|
| `blob` | string | Base64-encoded encrypted container |
| `expires_at` | string | ISO 8601 expiry timestamp. Empty if TTL is `never`. |
| `burn` | bool | Whether this paste will be deleted on next read |

**Response `404 Not Found`:**
Paste does not exist, has expired, or was burned.

```json
not found
```

---

### Delete Paste

```http
DELETE /api/paste/:id?token=<delete_token>
```

Requires the `delete_token` returned at creation time.

**Response `204 No Content`:**
Paste deleted successfully.

**Response `401 Unauthorized`:**
Invalid or missing token.

```json
unauthorized
```

---

## Container Format

The `blob` field contains a JSON structure with the encrypted content. See [Architecture: Container Format](../docs/ARCHITECTURE.md#container-format-json) for the full schema.

**Link-only container** — no password, key in URL fragment:

```json
{
  "v": 1,
  "m": 1,
  "c": "<base64 nonce+ciphertext+tag>"
}
```

**Password container** — password required, optional duress:

```json
{
  "v": 1,
  "m": 2,
  "s": { "r": "<salt>", "d": "<salt or null>" },
  "c": { "r": "<ciphertext>", "d": "<ciphertext or null>" },
  "w": { "r": "<wrapped key>", "d": "<wrapped key or null>" },
  "p": 0
}
```

## Rate Limiting

No rate limiting is enforced server-side on API endpoints. This is a deliberate design choice to avoid IP-based blocking (privacy trade-off). Brute-force protection is provided by the PBKDF2 KDF with 600,000 iterations — attempting one password guess requires significant client-side computation.

## Error Responses

| Status | Meaning |
|---|---|
| `400 Bad Request` | Invalid JSON body, missing fields, invalid TTL |
| `401 Unauthorized` | Invalid or missing delete token |
| `404 Not Found` | Paste does not exist, expired, or burned |
| `413 Request Entity Too Large` | Blob exceeds `NULLPASTE_MAXBYTES` (default 256 KiB) |
| `500 Internal Server Error` | Database or server error |
