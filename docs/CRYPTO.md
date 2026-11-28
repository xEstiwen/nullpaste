# Cryptographic Design

## Threat Model

Nullpaste assumes an adversary who can:
- Observe all network traffic (ISP, network operator, government)
- Access the server's database (database breach, malicious hosting provider)
- Read the open-source client code (public repository)

Nullpaste does **not** assume protection against:
- A compromised server that serves malicious JavaScript
- A compromised client browser
- Powerful offline brute-force (with weak passwords)

## Encryption Primitives

| Primitive | Choice | Rationale |
|---|---|---|
| AEAD | AES-GCM (256-bit) | Authenticated encryption, native to Web Crypto API |
| KDF | PBKDF2-SHA256, 600k iterations | Native to Web Crypto API, OWASP 2023 compliant |
| Key wrapping | AES-KW (AES Key Wrap) | Native to Web Crypto API, purpose-built for key wrapping |
| Nonce | 96-bit random per encryption | recommended for AES-GCM |

## Two Modes

### Mode 1 — Link-only

The content key is a random 256-bit value generated in the browser. It is placed in the URL fragment (`#k=...`) and never transmitted to the server. The server stores only the AES-GCM ciphertext.

```
content_key = crypto.getRandomValues(32 bytes)
ciphertext  = AES-GCM(content_key, plaintext)
server_blob = JSON.stringify({ v:1, m:1, c: base64(ciphertext) })
server_url  = /p/{id}#k={base64(content_key)}
```

The URL fragment is never included in HTTP requests per [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3.5) — the browser strips it before sending. A network observer sees the paste ID but not the key.

### Mode 2 — Password-protected with Duress

This mode stores two ciphertexts for the same logical paste, one real and one decoy. Each has its own salt, content key and wrapped key. Which of the two the server should treat as "real" cannot be told from the key material, because both wrapped keys are random-looking bytes. **The mode is not deniable against the server operator**, see [Known limitations of the duress mode](#known-limitations-of-the-duress-mode).

#### Key Hierarchy

```
user_password (real)
  └─ PBKDF2(pw, salt_real) = wrap_key_real
       └─ AES-KW unwrap wrap_key_real → content_key_real
            └─ AES-GCM decrypt → real_content

user_password (duress)
  └─ PBKDF2(pw, salt_duress) = wrap_key_duress
       └─ AES-KW unwrap wrap_key_duress → content_key_duress
            └─ AES-GCM decrypt → decoy_content
```

#### Why PBKDF2 + AES-KW?

PBKDF2 turns a user-chosen password into a uniform 256-bit key suitable for AES. The high iteration count (600,000) makes brute-force expensive.

AES-KW (Key Wrap) is purpose-built for wrapping one symmetric key with another. Unlike CTR or GCM mode, it has a constant-size output (always +8 bytes for a 256-bit key), which prevents leaking information about the wrapped key size.

#### Client Logic on Decrypt

```javascript
async function decrypt(jsonStr, password) {
  const c = JSON.parse(jsonStr);

  // try real password first
  try {
    const wrapKeyReal = deriveWrapKey(password, c.s.r);
    const contentKeyReal = unwrapKey(wrapKeyReal, c.w.r);
    const plaintext = AESGCMdecrypt(contentKeyReal, c.c.r);
    return { content: plaintext, isDuress: false };
  } catch { }

  // try duress password (if present)
  if (c.p === 1) {
    try {
      const wrapKeyDuress = deriveWrapKey(password, c.s.d);
      const contentKeyDuress = unwrapKey(wrapKeyDuress, c.w.d);
      const plaintext = AESGCMdecrypt(contentKeyDuress, c.c.d);
      return { content: plaintext, isDuress: true };
    } catch { }
  }

  throw new Error('wrong password');
}
```

**Timing note:** the real entry is tried first and the duress entry only after it fails, so entering the duress password takes about twice as long (two PBKDF2 derivations instead of one). The difference is not visible to the server, but anyone watching the screen while the paste opens can notice it.

#### Server's View

The server receives this JSON (with base64 blobs, which it sees as random bytes):

```json
{
  "v": 1,
  "m": 2,
  "s": { "r": "<random>", "d": "<random>" },
  "c": { "r": "<random>", "d": "<random>" },
  "w": { "r": "<random>", "d": "<random>" },
  "p": 1
}
```

Without the passwords, the server cannot tell which entry is "real". It can, however, tell **that a decoy exists**: the `p` flag says so, the `d` entries are `null` when no duress password was set, and the create request carries a `has_duress` field that the server stores. See the limitations below.

## What the Server Cannot Do

Given only the stored blob, the server cannot:

1. Determine the paste's content (encrypted)
2. Determine which of the two entries is the real one
3. Determine which password was used to access the paste (single GET request, no password transmitted)
4. Modify the paste without detection (AES-GCM authentication tag)

## Honest Security Analysis

### What protects content from a network observer?
The URL fragment containing the key never leaves the browser. The network sees only the paste ID (a random 128-bit token) and the encrypted blob.

### What protects content from a server compromise?
AES-GCM with a 256-bit key. Without the key (or password), the ciphertext is indistinguishable from random.

### What does the duress feature NOT protect against?
- **Compromised server serving malicious JS:** A malicious server could serve modified JavaScript that exfiltrates the password. This is inherent to any client-side web crypto system. The defense is: only use Nullpaste instances you trust, or verify the source code.
- **Compromised client browser:** A keylogger or browser extension can steal passwords. This is outside Nullpaste's threat model.
- **Offline brute-force of weak passwords:** An attacker with database access can brute-force the password offline. 600k PBKDF2 iterations significantly slows this down, but a determined attacker with GPU/ASIC resources can still break weak passwords. **Always use a strong, unique password.**

## Known limitations of the duress mode

These apply to the current format (container version 1). They are listed so that nobody relies on the duress mode for more than it gives.

1. **The server can see that a decoy exists.** The `p` flag, the `null` entries in `s`, `c` and `w` when no duress password is set, and the stored `has_duress` field all reveal it. Whoever operates the server, or obtains its database, knows which pastes carry a decoy.
2. **Ciphertext sizes are not padded.** Each ciphertext is the plaintext length plus 28 bytes. The server sees the size of the real and of the decoy content, and can see which is longer.
3. **Timing.** Entering the duress password takes about twice as long as entering the real one (see the timing note above).
4. **The two entries are not bound to each other.** There is no associated data tying a ciphertext to its role, so a malicious server could swap the `r` and `d` entries. The real password then opens the decoy slot and is reported as the duress password.
5. **The web application is part of the trust chain.** A server, or anyone who can alter what it serves, can ship JavaScript that sends the password or key away. This is inherent to browser-based encryption. Self-host, and only use an instance you trust.
6. **Burn-after-read can be used up by anyone who has the link.** The first successful request consumes the paste, whether or not it can decrypt it.

What the mode does protect against is a person who sees or demands the password for a paste: the duress password opens a plausible decoy and nothing on the screen shows that another entry exists. It does not protect against the operator of the server.

## Future Improvements

- **Argon2id** instead of PBKDF2: Better GPU/ASIC resistance. Available via `argon2-browser` WASM.
- **Ed25519Sign for delete tokens:** Current delete tokens are HMAC-based. A signed URL scheme would be more robust.
- **A deniable container:** always store two slots (the second filled with random bytes when no duress password is set), pad both to the same size, drop the `p` flag and the `has_duress` field, and always derive both keys so both outcomes take the same time. This would make the existence of a decoy invisible to the server.
