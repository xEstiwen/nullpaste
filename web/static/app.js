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

function buf2b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b642buf(str) {
  const bin = atob(str);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

async function generateKey() {
  return crypto.subtle.generateKey(
    { name: ALGORITHM, length: KEY_LENGTH }, true, ['encrypt', 'decrypt']
  );
}

async function deriveWrapKey(password, salt) {
  const material = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const sb = typeof salt === 'string' ? base64url2buf(salt) : salt;
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: sb, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-KW', length: KEY_LENGTH }, false, ['wrapKey', 'unwrapKey']
  );
}

async function encrypt(key, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const ct = await crypto.subtle.encrypt({ name: ALGORITHM, iv: nonce }, key, new TextEncoder().encode(plaintext));
  const out = new Uint8Array(nonce.length + ct.byteLength);
  out.set(nonce);
  out.set(new Uint8Array(ct), nonce.length);
  return out;
}

async function decrypt(key, combined) {
  const nonce = combined.slice(0, NONCE_LENGTH);
  const ct = combined.slice(NONCE_LENGTH);
  const pt = await crypto.subtle.decrypt({ name: ALGORITHM, iv: nonce }, key, ct);
  return new TextDecoder().decode(pt);
}

async function wrapKey(wk, k) {
  return buf2base64url(await crypto.subtle.wrapKey('raw', k, wk, { name: 'AES-KW' }));
}

async function unwrapKeyRaw(wk, w) {
  return crypto.subtle.unwrapKey('raw', base64url2buf(w), wk, { name: 'AES-KW' },
    { name: ALGORITHM, length: KEY_LENGTH }, false, ['encrypt', 'decrypt']);
}

async function exportKey(key) {
  return buf2base64url(await crypto.subtle.exportKey('raw', key));
}

async function importKey(kd) {
  const buf = typeof kd === 'string' ? base64url2buf(kd) : kd;
  return crypto.subtle.importKey('raw', buf, { name: ALGORITHM, length: KEY_LENGTH }, false, ['encrypt', 'decrypt']);
}

async function buildContainerPassword(content, decoyContent, password, duressPassword) {
  const saltReal = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const saltDecoy = duressPassword ? crypto.getRandomValues(new Uint8Array(SALT_LENGTH)) : null;

  const ckReal = await generateKey();
  const ckDecoy = duressPassword ? await generateKey() : null;

  const encReal = await encrypt(ckReal, content);
  const encDecoy = duressPassword && decoyContent ? await encrypt(ckDecoy, decoyContent) : (duressPassword ? await encrypt(ckDecoy, content) : null);

  const wkReal = await deriveWrapKey(password, saltReal);
  const wrReal = await wrapKey(wkReal, ckReal);

  let wrDecoy = null;
  if (duressPassword) {
    const wkDecoy = await deriveWrapKey(duressPassword, saltDecoy);
    wrDecoy = await wrapKey(wkDecoy, ckDecoy);
  }

  const container = {
    v: CONTAINER_VERSION, m: MODE_PASSWORD,
    s: { r: buf2base64url(saltReal), d: duressPassword ? buf2base64url(saltDecoy) : null },
    c: { r: buf2base64url(encReal), d: duressPassword ? buf2base64url(encDecoy) : null },
    w: { r: wrReal, d: wrDecoy },
    p: duressPassword ? 1 : 0,
  };
  return JSON.stringify(container);
}

async function decryptContainerPassword(jsonStr, password) {
  const c = JSON.parse(jsonStr);
  if (c.v !== CONTAINER_VERSION) throw new Error('invalid container');
  if (c.m !== MODE_PASSWORD) throw new Error('not a password container');

  try {
    const wk = await deriveWrapKey(password, c.s.r);
    const ck = await unwrapKeyRaw(wk, c.w.r);
    return { content: await decrypt(ck, base64url2buf(c.c.r)), isDuress: false };
  } catch {
    if (c.p === 1 && c.s.d && c.w.d) {
      try {
        const wk = await deriveWrapKey(password, c.s.d);
        const ck = await unwrapKeyRaw(wk, c.w.d);
        return { content: await decrypt(ck, base64url2buf(c.c.d)), isDuress: true };
      } catch {}
    }
    throw new Error('wrong password');
  }
}

async function buildContainerLinkOnly(content) {
  const key = await generateKey();
  const enc = await encrypt(key, content);
  const container = JSON.stringify({ v: CONTAINER_VERSION, m: MODE_LINKONLY, c: buf2base64url(enc) });
  return { container, key: await exportKey(key) };
}

async function decryptContainerLinkOnly(jsonStr, keyData) {
  const c = JSON.parse(jsonStr);
  if (c.v !== CONTAINER_VERSION) throw new Error('invalid container');
  if (c.m !== MODE_LINKONLY) throw new Error('not a link-only container');
  return decrypt(await importKey(keyData), base64url2buf(c.c));
}

function getPasteID() {
  const m = location.pathname.match(/\/p\/([^/]+)/);
  return m ? m[1] : null;
}

function getViewContext() {
  const h = location.hash.slice(1);
  if (!h) return null;
  if (h.startsWith('k=')) return { type: 'link', key: h.slice(2) };
  if (h.startsWith('p=1')) return { type: 'password' };
  return null;
}

function showError(msg) {
  const el = document.getElementById('error');
  if (el) { el.textContent = msg; el.style.display = 'block'; el.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
}

function hideError() {
  const el = document.getElementById('error');
  if (el) el.style.display = 'none';
}

function showContent(content, expiresAt, isDuress) {
  const el = document.getElementById('loading');
  if (el) el.style.display = 'none';
  const pp = document.getElementById('password-prompt');
  if (pp) pp.style.display = 'none';
  const imp = document.getElementById('import-section');
  if (imp) imp.style.display = 'none';
  const cv = document.getElementById('content-view');
  if (cv) cv.style.display = 'block';
  const dc = document.getElementById('decrypted-content');
  if (dc) dc.textContent = content;
  const meta = document.querySelector('.content-meta');
  if (meta) {
    meta.innerHTML = '';
    if (expiresAt && expiresAt !== '0001-01-01T00:00:00Z') {
      const b = document.createElement('span');
      b.className = 'badge';
      b.textContent = 'Expires ' + new Date(expiresAt).toLocaleString();
      meta.appendChild(b);
    }
    if (isDuress) {
      const b = document.createElement('span');
      b.className = 'badge duress';
      b.textContent = 'Decoy paste';
      meta.prepend(b);
    }
  }
}

// ====== Index page ======

function initIndex() {
  const pwBtn = document.getElementById('btn-pw-protect');
  const pwSection = document.getElementById('pw-section');
  const password = document.getElementById('password');
  const duressCheck = document.getElementById('enable-duress');
  const duressFields = document.getElementById('duress-fields');
  const duressSection = document.getElementById('duress-section');

  function updatePwVisibility() {
    const pwVal = password.value.trim();
    const pwActive = pwSection.style.display !== 'none' || pwVal.length > 0;
    if (!pwActive) {
      pwSection.style.display = 'none';
      duressSection.style.display = 'none';
      duressCheck.checked = false;
      duressFields.style.display = 'none';
      return;
    }
    pwSection.style.display = 'block';
    duressSection.style.display = pwVal.length > 0 ? 'block' : 'none';
    if (pwVal.length === 0) {
      duressCheck.checked = false;
      duressFields.style.display = 'none';
    }
  }

  if (pwBtn) {
    pwBtn.addEventListener('click', () => {
      const s = pwSection.style.display;
      pwSection.style.display = s === 'none' || !s ? 'block' : 'none';
      updatePwVisibility();
      pwBtn.classList.toggle('active', pwSection.style.display === 'block');
    });
  }

  if (password) {
    password.addEventListener('input', updatePwVisibility);
  }

  if (duressCheck) {
    duressCheck.addEventListener('change', () => {
      duressFields.style.display = duressCheck.checked ? 'block' : 'none';
    });
  }

  const createBtn = document.getElementById('create-btn');
  if (createBtn) createBtn.addEventListener('click', handleCreate);

  const encryptBtn = document.getElementById('encrypt-btn');
  if (encryptBtn) encryptBtn.addEventListener('click', handleEncrypt);

  document.getElementById('copy-btn')?.addEventListener('click', () => {
    const inp = document.getElementById('share-url');
    if (inp) {
      navigator.clipboard.writeText(inp.value).then(() => {
        document.getElementById('copy-btn').textContent = 'Copied!';
        setTimeout(() => { document.getElementById('copy-btn').textContent = 'Copy'; }, 1500);
      });
    }
  });

  document.getElementById('copy-export-btn')?.addEventListener('click', () => {
    const ct = document.getElementById('export-ciphertext');
    const key = document.getElementById('export-key');
    if (ct && key) {
      const text = '-----BEGIN NULLPASTE-----\n' + ct.value + '\n-----KEY-----\n' + key.value + '\n-----END NULLPASTE-----';
      navigator.clipboard.writeText(text).then(() => {
        document.getElementById('copy-export-btn').textContent = 'Copied!';
        setTimeout(() => { document.getElementById('copy-export-btn').textContent = 'Copy All'; }, 1500);
      });
    }
  });

  // tabs: share / export
  const tabLink = document.getElementById('tab-link');
  const tabExport = document.getElementById('tab-export');
  const createSection = document.getElementById('create-section');
  const exportSection = document.getElementById('export-section');

  if (tabLink && tabExport) {
    tabLink.addEventListener('click', () => {
      tabLink.classList.add('active');
      tabExport.classList.remove('active');
      createSection.style.display = 'block';
      exportSection.style.display = 'none';
    });
    tabExport.addEventListener('click', () => {
      tabExport.classList.add('active');
      tabLink.classList.remove('active');
      createSection.style.display = 'none';
      exportSection.style.display = 'block';
    });
  }
}

function hasPwProtection() {
  const pwSection = document.getElementById('pw-section');
  return pwSection && pwSection.style.display !== 'none' && document.getElementById('password').value.trim().length > 0;
}

async function handleCreate() {
  const content = document.getElementById('content').value;
  if (!content.trim()) { showError('Content is empty'); return; }

  const pw = hasPwProtection();
  const password = document.getElementById('password').value.trim();
  const duressEnabled = document.getElementById('enable-duress')?.checked;
  const duressPassword = duressEnabled ? (document.getElementById('duress-password').value.trim() || '') : '';
  const decoyContent = duressEnabled ? document.getElementById('duress-content').value : '';
  const ttl = document.getElementById('ttl').value;
  const burn = document.getElementById('burn').checked;
  const useDuress = pw && duressEnabled && password && duressPassword;

  if (useDuress && password === duressPassword) { showError('Duress password must differ from real password'); return; }

  const btn = document.getElementById('create-btn');
  btn.disabled = true;
  btn.textContent = 'Encrypting...';
  hideError();

  try {
    let blob, shareUrl;
    if (!pw) {
      const r = await buildContainerLinkOnly(content);
      blob = btoa(r.container);
      shareUrl = location.origin + '/p/{{id}}#k=' + r.key;
    } else {
      blob = btoa(await buildContainerPassword(content, decoyContent, password, useDuress ? duressPassword : ''));
      shareUrl = location.origin + '/p/{{id}}#p=1';
    }

    const resp = await fetch(API.create, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blob, ttl, burn, has_duress: useDuress }),
    });
    if (!resp.ok) { showError('Server error: ' + (await resp.text())); return; }

    const data = await resp.json();
    const finalUrl = shareUrl.replace('{{id}}', data.id);
    document.getElementById('share-url').value = finalUrl;
    document.getElementById('result').style.display = 'block';
    document.getElementById('result-link').style.display = 'block';
    document.getElementById('result-export').style.display = 'none';

    if (data.delete_token) {
      document.getElementById('delete-token').value = data.delete_token;
      document.getElementById('delete-token-row').style.display = 'block';
    }
    hideError();
    window.scrollTo(0, 0);
  } catch (e) {
    showError(e.message || 'Encryption failed');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Paste';
  }
}

async function handleEncrypt() {
  const content = document.getElementById('content').value;
  if (!content.trim()) { showError('Content is empty'); return; }

  const pw = hasPwProtection();
  const password = document.getElementById('password').value.trim();
  const duressEnabled = document.getElementById('enable-duress')?.checked;
  const duressPassword = duressEnabled ? (document.getElementById('duress-password').value.trim() || '') : '';
  const decoyContent = duressEnabled ? document.getElementById('duress-content').value : '';
  const useDuress = pw && duressEnabled && password && duressPassword;

  if (useDuress && password === duressPassword) { showError('Duress password must differ from real password'); return; }

  const btn = document.getElementById('encrypt-btn');
  btn.disabled = true;
  btn.textContent = 'Encrypting...';
  hideError();

  try {
    let ciphertext, keyVal;
    if (!pw) {
      const r = await buildContainerLinkOnly(content);
      ciphertext = btoa(r.container);
      keyVal = r.key;
    } else {
      ciphertext = btoa(await buildContainerPassword(content, decoyContent, password, useDuress ? duressPassword : ''));
      keyVal = '<password>';
    }

    document.getElementById('export-ciphertext').value = ciphertext;
    document.getElementById('export-key').value = keyVal;
    document.getElementById('result').style.display = 'block';
    document.getElementById('result-link').style.display = 'none';
    document.getElementById('result-export').style.display = 'block';
    document.getElementById('delete-token-row').style.display = 'none';
    hideError();
  } catch (e) {
    showError(e.message || 'Encryption failed');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Encrypt';
  }
}

// ====== View page ======

function initView() {
  const tabOpen = document.getElementById('tab-open');
  const tabImport = document.getElementById('tab-import');
  const decryptSection = document.getElementById('decrypt-section');
  const passwordPrompt = document.getElementById('password-prompt');
  const importSection = document.getElementById('import-section');
  const loading = document.getElementById('loading');

  if (tabOpen && tabImport) {
    tabOpen.addEventListener('click', () => {
      tabOpen.classList.add('active');
      tabImport.classList.remove('active');
      passwordPrompt.style.display = 'block';
      importSection.style.display = 'none';
    });
    tabImport.addEventListener('click', () => {
      tabImport.classList.add('active');
      tabOpen.classList.remove('active');
      importSection.style.display = 'block';
      passwordPrompt.style.display = 'none';
    });
  }

  document.getElementById('decrypt-btn')?.addEventListener('click', handleViewPassword);
  document.getElementById('import-decrypt-btn')?.addEventListener('click', handleImportDecrypt);

  const ctx = getViewContext();
  if (loading) loading.style.display = 'none';

  if (ctx && ctx.type === 'link') {
    handleViewLink(ctx.key);
  } else if (ctx && ctx.type === 'password') {
    if (passwordPrompt) passwordPrompt.style.display = 'block';
  } else {
    // no context, show import tab by default if no hash, else password
    const hash = location.hash.slice(1);
    if (!hash && location.pathname === '/static/view.html') {
      // showing import section
      if (tabImport) tabImport.click();
    } else if (passwordPrompt) {
      passwordPrompt.style.display = 'block';
    }
  }
}

async function handleViewPassword() {
  const pw = document.getElementById('password').value;
  if (!pw) return;
  const id = getPasteID();
  if (!id) { showError('No paste ID'); return; }

  const btn = document.getElementById('decrypt-btn');
  btn.disabled = true;
  btn.textContent = 'Decrypting...';
  hideError();

  try {
    const resp = await fetch(API.read(id));
    if (!resp.ok) { showError('Paste not found or expired'); return; }
    const data = await resp.json();
    const r = await decryptContainerPassword(atob(data.blob), pw);
    showContent(r.content, data.expires_at, r.isDuress);
  } catch (e) {
    showError(e.message || 'Decryption failed');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Decrypt';
  }
}

async function handleViewLink(keyData) {
  const id = getPasteID();
  if (!id) { showError('No paste ID'); return; }

  try {
    const resp = await fetch(API.read(id));
    if (!resp.ok) { showError('Paste not found or expired'); return; }
    const data = await resp.json();
    const content = await decryptContainerLinkOnly(atob(data.blob), keyData);
    showContent(content, data.expires_at, false);
  } catch (e) {
    showError(e.message || 'Decryption failed');
  }
}

async function handleImportDecrypt() {
  const ct = document.getElementById('import-ciphertext').value.trim();
  const key = document.getElementById('import-key').value.trim();
  if (!ct) { showError('No ciphertext'); return; }

  const btn = document.getElementById('import-decrypt-btn');
  btn.disabled = true;
  btn.textContent = 'Decrypting...';
  hideError();

  try {
    let jsonStr, result;
    // try as link-only: key is base64 key data
    if (key && key !== '<password>') {
      const container = atob(ct);
      result = { content: await decryptContainerLinkOnly(container, key), isDuress: false };
    } else {
      // password mode
      const container = atob(ct);
      const pw = key === '<password>' ? prompt('Enter the password:') : null;
      if (!pw) { showError('Password required'); return; }
      result = await decryptContainerPassword(container, pw);
    }
    showContent(result.content, null, result.isDuress);
  } catch (e) {
    showError(e.message || 'Decryption failed');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Decrypt from text';
  }
}

// ====== Init ======

if (location.pathname === '/' || location.pathname.endsWith('/index.html') || location.pathname.endsWith('/')) {
  initIndex();
} else {
  initView();
}
