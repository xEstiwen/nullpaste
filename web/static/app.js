const ALGORITHM = 'AES-GCM';
const KEY_LENGTH = 256;
const NONCE_LENGTH = 12;
const SALT_LENGTH = 16;
const PBKDF2_ITERATIONS = 600000;
const CONTAINER_VERSION = 1;
const MODE_LINKONLY = 1;
const MODE_PASSWORD = 2;

const API = {
  create: '/api/paste',
  read: (id) => `/api/paste/${id}`,
};

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function buf2base64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64url2buf(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf;
}

async function generateKey() {
  return crypto.subtle.generateKey(
    { name: ALGORITHM, length: KEY_LENGTH },
    true,
    ['encrypt', 'decrypt']
  );
}

async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password),
    'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

async function deriveWrapKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password),
    'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-KW', length: KEY_LENGTH },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

async function encrypt(key, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv: nonce },
    key,
    new TextEncoder().encode(plaintext)
  );
  const combined = new Uint8Array(nonce.length + ciphertext.byteLength);
  combined.set(nonce);
  combined.set(new Uint8Array(ciphertext), nonce.length);
  return combined;
}

async function decrypt(key, combined) {
  const nonce = combined.slice(0, NONCE_LENGTH);
  const ciphertext = combined.slice(NONCE_LENGTH);
  const plaintext = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv: nonce },
    key,
    ciphertext
  );
  return new TextDecoder().decode(plaintext);
}

async function wrapKey(wrapKey, keyToWrap) {
  const wrapped = await crypto.subtle.wrapKey('raw', keyToWrap, wrapKey, { name: 'AES-KW' });
  return buf2base64url(wrapped);
}

async function unwrapKeyRaw(unwrapKey, wrappedB64) {
  const wrapped = base64url2buf(wrappedB64);
  return crypto.subtle.unwrapKey(
    'raw', wrapped, unwrapKey,
    { name: 'AES-KW' },
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

async function exportKey(key) {
  return buf2base64url(await crypto.subtle.exportKey('raw', key));
}

async function importKey(keyData) {
  const buf = typeof keyData === 'string' ? base64url2buf(keyData) : keyData;
  return crypto.subtle.importKey(
    'raw', buf,
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

async function buildContainerPassword(content, password, duressPassword) {
  const saltReal = buf2base64url(crypto.getRandomValues(new Uint8Array(SALT_LENGTH)));
  const saltDecoy = duressPassword ? buf2base64url(crypto.getRandomValues(new Uint8Array(SALT_LENGTH))) : null;

  const contentKeyReal = await generateKey();
  const contentKeyDecoy = duressPassword ? await generateKey() : null;

  const encryptedReal = buf2base64url(await encrypt(contentKeyReal, content));
  const encryptedDecoy = duressPassword ? buf2base64url(await encrypt(contentKeyDecoy, content)) : null;

  const wrapKeyReal = await deriveWrapKey(password, saltReal);
  const wrappedReal = await wrapKey(wrapKeyReal, contentKeyReal);

  let wrappedDecoy = null;
  if (duressPassword) {
    const wrapKeyDecoy = await deriveWrapKey(duressPassword, saltDecoy);
    wrappedDecoy = await wrapKey(wrapKeyDecoy, contentKeyDecoy);
  }

  const container = {
    v: CONTAINER_VERSION,
    m: MODE_PASSWORD,
    s: { r: saltReal, d: saltDecoy },
    c: { r: encryptedReal, d: encryptedDecoy },
    w: { r: wrappedReal, d: wrappedDecoy },
    p: duressPassword ? 1 : 0,
  };

  return JSON.stringify(container);
}

async function decryptContainerPassword(jsonStr, password) {
  const c = JSON.parse(jsonStr);
  assert(c.v === CONTAINER_VERSION, 'unknown container version');
  assert(c.m === MODE_PASSWORD, 'not a password-protected container');

  try {
    const wrapKeyReal = await deriveWrapKey(password, c.s.r);
    const contentKeyReal = await unwrapKeyRaw(wrapKeyReal, c.w.r);
    const content = await decrypt(contentKeyReal, base64url2buf(c.c.r));
    return { content, isDuress: false };
  } catch {
    if (c.p === 1 && c.s.d && c.w.d) {
      try {
        const wrapKeyDecoy = await deriveWrapKey(password, c.s.d);
        const contentKeyDecoy = await unwrapKeyRaw(wrapKeyDecoy, c.w.d);
        const content = await decrypt(contentKeyDecoy, base64url2buf(c.c.d));
        return { content, isDuress: true };
      } catch {
        throw new Error('wrong password');
      }
    }
    throw new Error('wrong password');
  }
}

async function buildContainerLinkOnly(content) {
  const key = await generateKey();
  const encrypted = buf2base64url(await encrypt(key, content));
  const container = {
    v: CONTAINER_VERSION,
    m: MODE_LINKONLY,
    c: encrypted,
  };
  return { container: JSON.stringify(container), keyData: await exportKey(key) };
}

async function decryptContainerLinkOnly(jsonStr, keyData) {
  const c = JSON.parse(jsonStr);
  assert(c.v === CONTAINER_VERSION, 'unknown container version');
  assert(c.m === MODE_LINKONLY, 'not a link-only container');
  const key = await importKey(keyData);
  return decrypt(key, base64url2buf(c.c));
}

function getViewContext() {
  const hash = location.hash.slice(1);
  if (!hash) return null;
  if (hash.startsWith('k=')) return { type: 'link', key: hash.slice(2) };
  if (hash.startsWith('p=1')) return { type: 'password' };
  return null;
}

async function handleCreate() {
  const content = document.getElementById('content').value;
  if (!content.trim()) { showError('Content is empty'); return; }

  const password = document.getElementById('password').value;
  const duressPassword = document.getElementById('duress-password').value;
  const ttl = document.getElementById('ttl').value;
  const burn = document.getElementById('burn').checked;

  if (password && duressPassword && password === duressPassword) {
    showError('Duress password must be different from real password');
    return;
  }

  const btn = document.getElementById('create-btn');
  btn.disabled = true;
  btn.textContent = 'Encrypting...';

  try {
    let blob, shareUrl;
    if (!password) {
      const { container, keyData } = await buildContainerLinkOnly(content);
      blob = btoa(container);
      shareUrl = `${location.origin}/p/{{id}}#k=${keyData}`;
    } else {
      blob = btoa(await buildContainerPassword(content, password, duressPassword));
      shareUrl = `${location.origin}/p/{{id}}#p=1`;
    }

    const resp = await fetch(API.create, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blob, ttl, burn, has_duress: !!duressPassword }),
    });
    if (!resp.ok) {
      const err = await resp.text();
      showError('Server error: ' + err);
      return;
    }
    const data = await resp.json();
    const finalUrl = shareUrl.replace('{{id}}', data.id);
    document.getElementById('share-url').value = finalUrl;
    if (data.delete_token) {
      document.getElementById('delete-token').value = data.delete_token;
      document.getElementById('delete-token-row').style.display = 'block';
    }
    document.getElementById('result').style.display = 'block';
    document.getElementById('error').style.display = 'none';
  } catch (e) {
    showError(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Paste';
  }
}

function showError(msg) {
  const el = document.getElementById('error');
  el.textContent = msg;
  el.style.display = 'block';
}

function initIndex() {
  const passwordInput = document.getElementById('password');
  const duressGroup = document.getElementById('duress-group');
  passwordInput.addEventListener('input', () => {
    duressGroup.style.display = passwordInput.value ? 'block' : 'none';
  });
  document.getElementById('create-btn').addEventListener('click', handleCreate);
  document.getElementById('copy-btn').addEventListener('click', () => {
    const input = document.getElementById('share-url');
    navigator.clipboard.writeText(input.value);
    const btn = document.getElementById('copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
}

async function handleViewPassword() {
  const password = document.getElementById('password').value;
  if (!password) return;

  const btn = document.getElementById('decrypt-btn');
  btn.disabled = true;
  btn.textContent = 'Decrypting...';

  try {
    const id = location.hash.slice(1);
    const resp = await fetch(API.read(id));
    if (!resp.ok) { showError('Paste not found or expired'); return; }
    const data = await resp.json();
    const jsonStr = atob(data.blob);
    const result = await decryptContainerPassword(jsonStr, password);
    showContent(result.content, data.expires_at, result.isDuress);
  } catch (e) {
    showError('Decryption failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Decrypt';
  }
}

async function handleViewLink(keyData) {
  try {
    const id = location.hash.slice(1);
    const resp = await fetch(API.read(id));
    if (!resp.ok) { showError('Paste not found or expired'); return; }
    const data = await resp.json();
    const jsonStr = atob(data.blob);
    const content = await decryptContainerLinkOnly(jsonStr, keyData);
    showContent(content, data.expires_at, false);
  } catch (e) {
    showError('Decryption failed: ' + e.message);
  }
}

function showContent(content, expiresAt, isDuress) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('password-prompt').style.display = 'none';
  document.getElementById('content-view').style.display = 'block';
  document.getElementById('decrypted-content').textContent = content;
  const meta = document.querySelector('.content-meta');
  if (expiresAt) {
    const exp = new Date(expiresAt);
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = `Expires ${exp.toLocaleString()}`;
    meta.appendChild(badge);
  }
  if (isDuress) {
    const badge = document.createElement('span');
    badge.className = 'badge duress';
    badge.textContent = 'Decoy paste';
    meta.prepend(badge);
  }
}

function initView() {
  const ctx = getViewContext();
  document.getElementById('loading').style.display = 'none';
  if (!ctx) {
    document.getElementById('password-prompt').style.display = 'block';
    return;
  }
  if (ctx.type === 'link') {
    handleViewLink(ctx.key);
  } else {
    document.getElementById('password-prompt').style.display = 'block';
    document.getElementById('decrypt-btn').addEventListener('click', handleViewPassword);
  }
}

if (location.pathname === '/' || location.pathname.endsWith('/index.html')) {
  initIndex();
} else {
  initView();
}
