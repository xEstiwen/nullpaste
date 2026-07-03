# Security Analysis — Nullpaste

## Threat Model

Nullpaste assumes an adversary who can:
- Observe all network traffic (ISP, network operator, government)
- Access the server's database (breach, malicious hosting provider)
- Read the open-source client code (public repository)

Nullpaste does **not** protect against:
- A compromised server that serves malicious JavaScript
- A compromised client browser (keyloggers, extensions)
- Weak user passwords (offline brute-force)

## What Can an Attacker Extract?

### Attack: Database breach

| Data | Attacker obtains | Risk |
|---|---|---|
| Paste ID | Random 128-bit token | Low — no content revealed |
| Encrypted blob | AES-GCM 256-bit ciphertext | **Negligible** — cannot decrypt without key |
| Timestamps | Creation & expiry dates | Low — metadata only |
| Burn flag | Boolean | Low — reveals burn policy |
| Duress flag | Boolean | Medium — reveals duress existence |
| Delete hash | SHA-256 hash of token | Low — cannot reverse to original token |

### Attack: Network interception

| Data | Attacker sees | Risk |
|---|---|---|
| Paste ID | In URL path | Low — no key in path |
| Encrypted blob | In HTTP body | **Negligible** — encrypted |
| Timestamps / flags | In JSON body | Low — metadata |
| **Encryption key** | **Not transmitted** | **Zero** — stays in URL fragment, never sent |
| **Password** | **Not transmitted** | **Zero** — stays in browser memory |
| **Plaintext** | **Not transmitted** | **Zero** — encrypted before upload |

### Attack: Compromised server (malicious JS)

| Data | Attacker obtains | Notes |
|---|---|---|
| Password | Yes | If served malicious JS that exfiltrates input |
| Encryption key | Yes | If served malicious JS that reads fragment |
| Plaintext | Yes | If served malicious JS that uploads before encrypting |
| **Mitigation** | **Self-host or verify source** | Only use instances you trust |

## Cryptographic Properties

| Property | How it's achieved |
|---|---|
| Confidentiality | AES-GCM 256-bit, key never transmitted |
| Integrity | AES-GCM authentication tag, tampering detected |
| Forward secrecy | Not provided — compromise reveals all pastes |
| Deniability | Two ciphertexts (real + decoy), server cannot distinguish |
| KDF strength | PBKDF2-SHA256, 600,000 iterations (OWASP 2023) |
| Key wrapping | AES-KW (NIST SP 800-38F) |

## Attack Scenarios

### 1. Passive network observer
Sees: paste ID, encrypted blob, timestamps.
Cannot: decrypt, determine duress usage, learn passwords.

### 2. Server DB breach
Obtains: encrypted blobs, metadata.
Cannot: decrypt, because keys are client-side only.

### 3. Man-in-the-middle
Cannot: modify blob undetected (AES-GCM tag).
Can: drop requests (DoS).

### 4. Legal coercion (subpoena)
Server can provide: encrypted blob, timestamps, burn flags.
Cannot provide: content, keys, passwords, IP addresses.

### 5. Offline brute-force
Attacker with DB dump can try passwords against PBKDF2-wrapped keys.
600k iterations ≈ 2-3 attempts/sec per core on CPU. A weak password (e.g., 4 lowercase letters) can be cracked in hours. A strong password (12+ random chars) is infeasible.

## Security Headers

The server sets:

| Header | Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline'` | Prevents XSS |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing |
| `X-Burned` | `1` | Indicates paste was burned on this read |

## Rate Limiting

There is no rate limiting on API endpoints. This is a deliberate choice:
- IP-based rate limiting conflicts with privacy (we don't log IPs)
- ID-based rate limiting creates a DoS vector (attacker can exhaust limit on a paste)
- The primary defense against brute-force is the PBKDF2 KDF

## Future Security Improvements

- **Argon2id** instead of PBKDF2: better GPU/ASIC resistance
- **Ed25519 signatures** for delete tokens: more robust than HMAC
- **VeraCrypt-style hidden volumes**: same-size ciphertexts for real and decoy
- **Database encryption** at rest (e.g., SQLCipher)
- **Audit logging** (opt-in): log access counts without IP/UA
