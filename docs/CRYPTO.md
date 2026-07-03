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

This mode uses **deniable encryption**: two ciphertexts exist for the same logical paste, one real and one decoy. The server cannot determine which password is "real" because both wrapped keys are indistinguishable random bytes.

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

**Constant-time note:** The two unwrap attempts happen sequentially in JavaScript. JavaScript runtimes do not guarantee constant-time execution, so a local attacker with a debugger could observe timing differences. This is a known limitation of browser-based zero-knowledge systems. The timing difference is on the order of nanoseconds and is not observable over a network.

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

Without the passwords, the server cannot determine which entry is "real." Both ciphertexts and both wrapped keys are indistinguishable from random bytes. The `p` flag (`has_duress`) is set by the client, but the server does not interpret it — it is metadata that helps the client know whether to try the duress branch.

## What the Server Cannot Do

Given only the stored blob, the server cannot:

1. Determine the paste's content (encrypted)
2. Determine whether a duress password exists (it can read the `p` flag but cannot verify it)
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

## Future Improvements

- **Argon2id** instead of PBKDF2: Better GPU/ASIC resistance. Available via `argon2-browser` WASM.
- **Ed25519Sign for delete tokens:** Current delete tokens are HMAC-based. A signed URL scheme would be more robust.
- **VeraCrypt-style plausible deniability:** The two ciphertexts could be the same size, further hiding which is "real."
