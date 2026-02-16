/* ═══════════════════════════════════════════════════════════
   Wolfronix Test App — Application Logic
   
   This talks directly to the Wolfronix REST API.
   No SDK build step needed — pure browser JS.
   ═══════════════════════════════════════════════════════════ */

// ─── State ───
let config = { baseUrl: '', clientId: '', wolfronixKey: '' };
let auth = { userId: null, loggedIn: false };
let lastEncryptedMsg = null; // for quick decrypt

// ─── Tab Navigation ───
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
});

// ─── API Helper ───
async function api(method, endpoint, body, isFormData = false) {
    const url = config.baseUrl + endpoint;
    const headers = {};

    if (config.wolfronixKey) headers['X-Wolfronix-Key'] = config.wolfronixKey;
    if (config.clientId) headers['X-Client-ID'] = config.clientId;
    if (auth.userId) headers['X-User-ID'] = auth.userId;
    if (body && !isFormData) headers['Content-Type'] = 'application/json';

    const opts = { method, headers };
    if (body) {
        opts.body = isFormData ? body : JSON.stringify(body);
    }

    const startTime = Date.now();
    let response, data, error;

    try {
        response = await fetch(url, opts);
        const contentType = response.headers.get('content-type') || '';

        if (contentType.includes('application/json')) {
            data = await response.json();
        } else if (contentType.includes('octet-stream') || contentType.includes('application/')) {
            data = await response.blob();
        } else {
            const text = await response.text();
            try { data = JSON.parse(text); } catch { data = text; }
        }

        if (!response.ok) {
            error = (data && data.error) || (data && typeof data === 'string' ? data : `HTTP ${response.status}`);
        }
    } catch (e) {
        error = e.message;
    }

    const elapsed = Date.now() - startTime;

    // Log
    addLog(method, endpoint, response?.status, elapsed, body && !isFormData ? body : null, error ? { error } : data);

    if (error) throw new Error(error);
    return data;
}

// ─── Connect / Health Check ───
async function initClient() {
    // Default to same origin if no URL entered (when served from nginx)
    const serverUrl = (document.getElementById('serverUrl').value || window.location.origin).replace(/\/$/, '');
    const clientId = document.getElementById('clientId').value.trim();
    const wolfronixKey = document.getElementById('wolfronixKey').value.trim();

    if (!serverUrl) return alert('Server URL is required');

    config = { baseUrl: serverUrl, clientId, wolfronixKey };

    const badge = document.getElementById('status-badge');
    badge.className = 'badge badge-degraded';
    badge.textContent = 'Connecting...';

    try {
        const health = await api('GET', '/health');
        if (health.status === 'healthy') {
            badge.className = 'badge badge-connected';
            badge.textContent = 'Connected — DB: ' + (health.database || 'ok');
        } else if (health.status === 'degraded') {
            badge.className = 'badge badge-degraded';
            badge.textContent = 'Degraded — DB: ' + (health.database || '?');
        }
    } catch (e) {
        badge.className = 'badge badge-disconnected';
        badge.textContent = 'Failed: ' + e.message;
    }
}

// ─── Auth: Register ───
async function doRegister() {
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regPassword').value;
    if (!email || !password) return alert('Email and password required');

    setBusy('Generating keys...');

    try {
        // 1. Generate RSA key pair in browser
        const keyPair = await window.crypto.subtle.generateKey(
            { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
            true, ['encrypt', 'decrypt']
        );

        // 2. Export public key as PEM
        const pubDer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const pubPem = derToPem(pubDer, 'PUBLIC KEY');

        // 3. Wrap private key with password (PBKDF2 → AES-GCM)
        const { encryptedKey, salt } = await wrapPrivateKey(keyPair.privateKey, password);

        // 4. Register on server
        const resp = await api('POST', '/api/v1/keys/register', {
            client_id: config.clientId,
            user_id: email,
            public_key_pem: pubPem,
            encrypted_private_key: encryptedKey,
            salt: salt
        });

        // 5. Store keys in memory
        auth = { userId: email, loggedIn: true };
        window._keys = { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, pubPem };
        showUserInfo();
        clearBusy();
        showToast('Registered successfully!', 'success');
    } catch (e) {
        clearBusy();
        showToast('Register failed: ' + e.message, 'error');
    }
}

// ─── Auth: Login ───
async function doLogin() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    if (!email || !password) return alert('Email and password required');

    setBusy('Fetching keys...');

    try {
        // 1. Fetch encrypted keys from server
        const resp = await api('POST', '/api/v1/keys/login', {
            client_id: config.clientId,
            user_id: email
        });

        if (!resp.encrypted_private_key || !resp.salt) {
            throw new Error('User not found or keys missing');
        }

        // 2. Unwrap private key with password
        const privateKey = await unwrapPrivateKey(resp.encrypted_private_key, password, resp.salt);

        // 3. Import public key
        const publicKey = await importPemPublicKey(resp.public_key_pem);

        auth = { userId: email, loggedIn: true };
        window._keys = { publicKey, privateKey, pubPem: resp.public_key_pem };
        showUserInfo();
        clearBusy();
        showToast('Logged in!', 'success');
    } catch (e) {
        clearBusy();
        showToast('Login failed: ' + e.message, 'error');
    }
}

// ─── Auth: Logout ───
function doLogout() {
    auth = { userId: null, loggedIn: false };
    window._keys = null;
    document.getElementById('user-info').style.display = 'none';
    showToast('Logged out', 'success');
}

function showUserInfo() {
    document.getElementById('user-info').style.display = '';
    document.getElementById('currentUser').textContent = auth.userId;
    document.getElementById('keyStatus').textContent = window._keys ? '✅ RSA keys loaded in memory' : '❌ No keys';
}

// ─── Files: Encrypt ───
async function doEncrypt() {
    requireAuth();
    const fileInput = document.getElementById('fileInput');
    if (!fileInput.files.length) return alert('Select a file first');

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    formData.append('user_id', auth.userId);
    if (window._keys?.pubPem) {
        formData.append('client_public_key', window._keys.pubPem);
    }

    setBusy('Encrypting...');
    try {
        const resp = await api('POST', '/api/v1/encrypt', formData, true);
        const box = document.getElementById('encryptResult');
        box.style.display = '';
        box.className = 'result-box success';
        box.textContent = JSON.stringify(resp, null, 2);
        clearBusy();
        showToast('File encrypted! ID: ' + (resp.file_id || 'N/A'), 'success');
    } catch (e) {
        clearBusy();
        showResult('encryptResult', e.message, true);
    }
}

// ─── Files: List ───
async function doListFiles() {
    requireAuth();
    try {
        const files = await api('GET', '/api/v1/files');
        const container = document.getElementById('fileList');

        if (!files || (Array.isArray(files) && files.length === 0)) {
            container.innerHTML = '<p class="placeholder">No files found</p>';
            return;
        }

        const arr = Array.isArray(files) ? files : [files];
        container.innerHTML = arr.map(f => `
            <div class="file-item">
                <div>
                    <div class="file-name">${esc(f.name || f.original_name || 'unnamed')}</div>
                    <div class="file-meta">ID: ${f.id || f.file_id} · ${formatBytes(f.size_bytes || f.encrypted_size || 0)} · ${f.date || f.created_at || '—'}</div>
                </div>
                <div class="file-item-actions">
                    <button onclick="doDecryptById('${f.id || f.file_id}')">Decrypt</button>
                    <button class="btn-delete" onclick="doDelete('${f.id || f.file_id}')">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (e) {
        showToast('List files failed: ' + e.message, 'error');
    }
}

// ─── Files: Decrypt ───
async function doDecrypt() {
    const fileId = document.getElementById('decryptFileId').value.trim();
    if (!fileId) return alert('Enter a File ID');
    await doDecryptById(fileId);
}

async function doDecryptById(fileId) {
    requireAuth();
    if (!window._keys?.privateKey) return alert('No private key loaded. Please login first.');

    setBusy('Decrypting...');
    try {
        // Step 1: Get encrypted key_part_a
        const keyResp = await api('GET', `/api/v1/files/${fileId}/key`);

        // Step 2: Decrypt key_part_a with our private key (RSA-OAEP)
        const encKeyBytes = base64ToBytes(keyResp.key_part_a);
        const decKeyBytes = await window.crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            window._keys.privateKey,
            encKeyBytes
        );
        const decryptedKeyA = bytesToBase64(new Uint8Array(decKeyBytes));

        // Step 3: Send decrypted key back → get file
        const blob = await api('POST', `/api/v1/files/${fileId}/decrypt`, {
            decrypted_key_a: decryptedKeyA,
            user_role: 'owner'
        });

        // Download the file
        if (blob instanceof Blob) {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `decrypted_${fileId}`;
            a.click();
            URL.revokeObjectURL(url);
        }

        clearBusy();
        showToast('File decrypted & downloaded!', 'success');
    } catch (e) {
        clearBusy();
        showToast('Decrypt failed: ' + e.message, 'error');
    }
}

// ─── Files: Delete ───
async function doDelete(fileId) {
    requireAuth();
    if (!confirm('Delete file ' + fileId + '?')) return;

    try {
        await api('DELETE', `/api/v1/files/${fileId}`);
        showToast('File deleted', 'success');
        doListFiles(); // refresh
    } catch (e) {
        showToast('Delete failed: ' + e.message, 'error');
    }
}

// ─── Messages: Server Encrypt ───
async function doMsgEncrypt() {
    requireAuth();
    const message = document.getElementById('msgPlain').value.trim();
    if (!message) return alert('Enter a message');

    const layer = parseInt(document.getElementById('msgLayer').value);

    setBusy('Encrypting message...');
    try {
        const resp = await api('POST', '/api/v1/messages/encrypt', {
            message,
            user_id: auth.userId,
            layer
        });

        lastEncryptedMsg = resp;
        document.getElementById('decryptMsgBtn').disabled = false;

        showResult('msgEncResult', JSON.stringify(resp, null, 2));
        clearBusy();
        showToast('Message encrypted!', 'success');
    } catch (e) {
        clearBusy();
        showResult('msgEncResult', e.message, true);
    }
}

// ─── Messages: Server Decrypt ───
async function doMsgDecrypt() {
    requireAuth();
    if (!lastEncryptedMsg) return alert('Encrypt a message first');

    setBusy('Decrypting...');
    try {
        const resp = await api('POST', '/api/v1/messages/decrypt', {
            encrypted_message: lastEncryptedMsg.encrypted_message,
            nonce: lastEncryptedMsg.nonce,
            key_part_a: lastEncryptedMsg.key_part_a,
            message_tag: lastEncryptedMsg.message_tag || '',
            user_id: auth.userId
        });

        showResult('msgDecResult', '✅ Decrypted: ' + (resp.message || JSON.stringify(resp)));
        clearBusy();
    } catch (e) {
        clearBusy();
        showResult('msgDecResult', e.message, true);
    }
}

// ─── Messages: Batch Encrypt ───
async function doBatchEncrypt() {
    requireAuth();
    const text = document.getElementById('batchMsgs').value.trim();
    if (!text) return alert('Enter messages (one per line)');

    const lines = text.split('\n').filter(l => l.trim());
    const messages = lines.map((msg, i) => ({ id: 'msg_' + (i + 1), message: msg.trim() }));

    setBusy('Batch encrypting...');
    try {
        const resp = await api('POST', '/api/v1/messages/batch/encrypt', {
            messages,
            user_id: auth.userId,
            layer: 4
        });

        showResult('batchResult', JSON.stringify(resp, null, 2));
        clearBusy();
        showToast(`${messages.length} messages encrypted!`, 'success');
    } catch (e) {
        clearBusy();
        showResult('batchResult', e.message, true);
    }
}

// ═══════════════════════════════════════════════════════════
// Crypto Helpers (browser Web Crypto API)
// ═══════════════════════════════════════════════════════════

function derToPem(der, label) {
    const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
    const lines = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToDer(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}

async function wrapPrivateKey(privateKey, password) {
    // Export private key
    const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', privateKey);

    // Derive wrapping key from password (PBKDF2 → AES-GCM-256)
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();

    const keyMaterial = await window.crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const aesKey = await window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );

    const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, pkcs8);

    // Pack: iv(12) + ciphertext
    const packed = new Uint8Array(iv.length + encrypted.byteLength);
    packed.set(iv);
    packed.set(new Uint8Array(encrypted), iv.length);

    return {
        encryptedKey: bytesToBase64(packed),
        salt: bytesToHex(salt)
    };
}

async function unwrapPrivateKey(encryptedKeyB64, password, saltHex) {
    const packed = base64ToBytes(encryptedKeyB64);
    const iv = packed.slice(0, 12);
    const ciphertext = packed.slice(12);
    const salt = hexToBytes(saltHex);
    const enc = new TextEncoder();

    const keyMaterial = await window.crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const aesKey = await window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    const pkcs8 = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);

    return window.crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
}

async function importPemPublicKey(pem) {
    const der = pemToDer(pem);
    return window.crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
}

// ─── Base64 / Hex Helpers ───
function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
}

// ═══════════════════════════════════════════════════════════
// UI Helpers
// ═══════════════════════════════════════════════════════════

function requireAuth() {
    if (!auth.loggedIn) {
        showToast('Please login first', 'error');
        throw new Error('Not logged in');
    }
}

function showResult(id, text, isError = false) {
    const el = document.getElementById(id);
    el.style.display = '';
    el.className = 'result-box ' + (isError ? 'error' : 'success');
    el.textContent = text;
}

function setBusy(msg) {
    document.title = '⏳ ' + msg + ' — Wolfronix';
}

function clearBusy() {
    document.title = 'Wolfronix Test App';
}

function showToast(msg, type) {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed; top: 16px; right: 16px; z-index: 9999;
        padding: 12px 20px; border-radius: 8px; font-size: 13px; font-weight: 600;
        background: ${type === 'error' ? '#f85149' : '#3fb950'}; color: #fff;
        box-shadow: 0 4px 12px rgba(0,0,0,0.4); transition: opacity 0.3s;
    `;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 3000);
}

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}

// ─── Logging ───
function addLog(method, endpoint, status, elapsed, requestBody, responseBody) {
    const container = document.getElementById('logContainer');
    const now = new Date().toLocaleTimeString();
    const ok = status && status >= 200 && status < 300;

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span class="log-time">${now}</span>
        <span class="log-method ${method}">${method}</span>
        <span class="log-url">${esc(endpoint)}</span>
        <span class="log-status ${ok ? 'ok' : 'err'}">${status || 'ERR'}</span>
        <span style="color:var(--text2);margin-left:8px;">${elapsed}ms</span>
        ${responseBody ? `<div class="log-body">${esc(typeof responseBody === 'object' ? JSON.stringify(responseBody, null, 2) : String(responseBody))}</div>` : ''}
    `;
    container.prepend(entry);
}

function clearLogs() {
    document.getElementById('logContainer').innerHTML = '';
}
