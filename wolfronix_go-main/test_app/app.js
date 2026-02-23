/* ═══════════════════════════════════════════════════════════
   Wolfronix Test App — Application Logic
   
   Uses the official @wolfronix/sdk (loaded via wolfronix.browser.js)
   All crypto and API calls go through the SDK.
   ═══════════════════════════════════════════════════════════ */

// ─── State ───
let wfx = null;       // Wolfronix SDK instance
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

// ─── Connect / Health Check ───
async function initClient() {
    const serverUrl = (document.getElementById('serverUrl').value || window.location.origin).replace(/\/$/, '');
    const clientId = document.getElementById('clientId').value.trim();
    const wolfronixKey = document.getElementById('wolfronixKey').value.trim();

    if (!serverUrl) return alert('Server URL is required');

    // Create SDK instance
    wfx = new WolfronixSDK.Wolfronix({
        baseUrl: serverUrl,
        clientId: clientId,
        wolfronixKey: wolfronixKey,
        insecure: true,   // Allow self-signed certs
        timeout: 300000,   // 5 min timeout for large files
        retries: 1
    });

    const badge = document.getElementById('status-badge');
    badge.className = 'badge badge-degraded';
    badge.textContent = 'Connecting...';

    try {
        // Health check (direct fetch since SDK doesn't have a health method)
        const resp = await fetch(serverUrl + '/health', {
            headers: wolfronixKey ? { 'X-Wolfronix-Key': wolfronixKey } : {}
        });
        const health = await resp.json();

        if (health.status === 'healthy') {
            badge.className = 'badge badge-connected';
            badge.textContent = 'Connected — DB: ' + (health.database || 'ok');
        } else if (health.status === 'degraded') {
            badge.className = 'badge badge-degraded';
            badge.textContent = 'Degraded — DB: ' + (health.database || '?');
        }
        addLog('GET', '/health', resp.status, 0, null, health);
    } catch (e) {
        badge.className = 'badge badge-disconnected';
        badge.textContent = 'Failed: ' + e.message;
        addLog('GET', '/health', 0, 0, null, { error: e.message });
    }
}

// ─── Auth: Register ───
async function doRegister() {
    requireSDK();
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regPassword').value;
    if (!email || !password) return alert('Email and password required');

    setBusy('Generating keys & registering...');

    try {
        const start = Date.now();
        const resp = await wfx.register(email, password);
        const elapsed = Date.now() - start;

        addLog('POST', '/api/v1/keys/register', 200, elapsed, { user_id: email }, resp);
        showUserInfo();
        clearBusy();
        showToast('Registered successfully via SDK!', 'success');
    } catch (e) {
        clearBusy();
        addLog('POST', '/api/v1/keys/register', e.statusCode || 0, 0, null, { error: e.message });
        showToast('Register failed: ' + e.message, 'error');
    }
}

// ─── Auth: Login ───
async function doLogin() {
    requireSDK();
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    if (!email || !password) return alert('Email and password required');

    setBusy('Fetching & unwrapping keys...');

    try {
        const start = Date.now();
        const resp = await wfx.login(email, password);
        const elapsed = Date.now() - start;

        addLog('POST', '/api/v1/keys/login', 200, elapsed, { user_id: email }, resp);
        showUserInfo();
        clearBusy();
        showToast('Logged in via SDK!', 'success');
    } catch (e) {
        clearBusy();
        addLog('POST', '/api/v1/keys/login', e.statusCode || 0, 0, null, { error: e.message });
        showToast('Login failed: ' + e.message, 'error');
    }
}

// ─── Auth: Logout ───
function doLogout() {
    if (wfx) wfx.logout();
    document.getElementById('user-info').style.display = 'none';
    showToast('Logged out', 'success');
}

function showUserInfo() {
    document.getElementById('user-info').style.display = '';
    document.getElementById('currentUser').textContent = wfx.getUserId();
    document.getElementById('keyStatus').textContent = wfx.hasPrivateKey()
        ? '✅ RSA keys loaded in memory (SDK)'
        : '❌ No keys';
}

// ─── Files: Encrypt ───
async function doEncrypt() {
    requireAuth();
    const fileInput = document.getElementById('fileInput');
    if (!fileInput.files.length) return alert('Select a file first');

    const file = fileInput.files[0];
    setBusy(`Encrypting ${file.name} (${formatBytes(file.size)})...`);

    try {
        const start = Date.now();
        const resp = await wfx.encrypt(file);
        const elapsed = Date.now() - start;

        const box = document.getElementById('encryptResult');
        box.style.display = '';
        box.className = 'result-box success';
        box.textContent = JSON.stringify(resp, null, 2);

        addLog('POST', '/api/v1/encrypt', 200, elapsed, { filename: file.name, size: file.size }, resp);
        clearBusy();
        showToast('File encrypted! ID: ' + (resp.file_id || 'N/A'), 'success');
    } catch (e) {
        clearBusy();
        addLog('POST', '/api/v1/encrypt', e.statusCode || 500, 0, null, { error: e.message });
        showResult('encryptResult', e.message, true);
    }
}

// ─── Files: List ───
async function doListFiles() {
    requireAuth();
    try {
        const start = Date.now();
        const resp = await wfx.listFiles();
        const elapsed = Date.now() - start;

        addLog('GET', '/api/v1/files', 200, elapsed, null, resp);

        const container = document.getElementById('fileList');
        const files = resp.files || [];

        if (files.length === 0) {
            container.innerHTML = '<p class="placeholder">No files found</p>';
            return;
        }

        container.innerHTML = files.map(f => `
            <div class="file-item">
                <div>
                    <div class="file-name">${esc(f.original_name || 'unnamed')}</div>
                    <div class="file-meta">ID: ${f.file_id} · ${formatBytes(f.encrypted_size || 0)} · ${f.created_at || '—'}</div>
                </div>
                <div class="file-item-actions">
                    <button onclick="doDecryptById('${f.file_id}')">Decrypt</button>
                    <button class="btn-delete" onclick="doDelete('${f.file_id}')">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (e) {
        addLog('GET', '/api/v1/files', e.statusCode || 500, 0, null, { error: e.message });
        showToast('List files failed: ' + e.message, 'error');
    }
}

// ─── Files: Decrypt ───
async function doDecrypt() {
    const fileId = document.getElementById('decryptFileId').value.trim();
    if (!fileId) return alert('Enter a File ID');
    await doDecryptById(fileId);
}

// Current preview state for download
let currentPreviewBlob = null;
let currentPreviewName = '';

async function doDecryptById(fileId) {
    requireAuth();

    setBusy('Decrypting...');
    try {
        const start = Date.now();

        // SDK handles the full zero-knowledge flow:
        // 1. GET /files/{id}/key → encrypted key_part_a
        // 2. RSA decrypt key_part_a client-side
        // 3. POST /files/{id}/decrypt with decrypted_key_a
        const blob = await wfx.decrypt(fileId);
        const elapsed = Date.now() - start;

        addLog('POST', `/api/v1/files/${fileId}/decrypt`, 200, elapsed, null, { size: blob.size });

        // Show preview
        currentPreviewBlob = blob;
        currentPreviewName = `decrypted_${fileId}`;
        showPreview(blob, fileId);

        clearBusy();
        showToast('File decrypted successfully via SDK!', 'success');
    } catch (e) {
        clearBusy();
        addLog('POST', `/api/v1/files/${fileId}/decrypt`, e.statusCode || 500, 0, null, { error: e.message });
        showToast('Decrypt failed: ' + e.message, 'error');
    }
}

// ─── Preview Panel ───
function showPreview(blob, fileId) {
    const card = document.getElementById('previewCard');
    const content = document.getElementById('previewContent');
    const title = document.getElementById('previewTitle');

    title.textContent = `Decrypted File #${fileId}`;
    content.innerHTML = '';
    card.style.display = 'block';

    const type = blob.type || '';
    const name = currentPreviewName.toLowerCase();

    // Image
    if (type.startsWith('image/') || /\.(png|jpg|jpeg|gif|webp|svg|bmp|ico)$/i.test(name)) {
        const img = document.createElement('img');
        img.src = URL.createObjectURL(blob);
        img.className = 'preview-image';
        img.onload = () => URL.revokeObjectURL(img.src);
        content.appendChild(img);
        return;
    }

    // PDF
    if (type === 'application/pdf' || name.endsWith('.pdf')) {
        const iframe = document.createElement('iframe');
        iframe.src = URL.createObjectURL(blob);
        iframe.className = 'preview-pdf';
        content.appendChild(iframe);
        return;
    }

    // Video
    if (type.startsWith('video/') || /\.(mp4|webm|ogg|mov)$/i.test(name)) {
        const video = document.createElement('video');
        video.src = URL.createObjectURL(blob);
        video.controls = true;
        video.className = 'preview-video';
        content.appendChild(video);
        return;
    }

    // Audio
    if (type.startsWith('audio/') || /\.(mp3|wav|ogg|flac|m4a)$/i.test(name)) {
        const audio = document.createElement('audio');
        audio.src = URL.createObjectURL(blob);
        audio.controls = true;
        audio.className = 'preview-audio';
        content.appendChild(audio);
        return;
    }

    // Text / JSON / CSV / code
    if (type.startsWith('text/') || type.includes('json') || type.includes('xml') ||
        /\.(txt|csv|json|xml|html|css|js|ts|md|log|yaml|yml|env|sql|py|go|java|c|cpp|h|sh|bat|ini|cfg|toml)$/i.test(name) ||
        blob.size < 2 * 1024 * 1024) {
        blob.text().then(text => {
            const nullCount = (text.match(/\0/g) || []).length;
            if (nullCount > text.length * 0.1) {
                showBinaryPreview(content, blob);
                return;
            }
            const pre = document.createElement('pre');
            pre.className = 'preview-text';
            pre.textContent = text;
            content.appendChild(pre);
        }).catch(() => showBinaryPreview(content, blob));
        return;
    }

    showBinaryPreview(content, blob);
}

function showBinaryPreview(container, blob) {
    container.innerHTML = `
        <div class="preview-binary">
            <div class="preview-binary-icon">📄</div>
            <div>Binary file · ${formatBytes(blob.size)}</div>
            <div class="preview-binary-type">${blob.type || 'unknown type'}</div>
            <button onclick="downloadPreview()" style="margin-top:12px">⬇ Download File</button>
        </div>
    `;
}

function downloadPreview() {
    if (!currentPreviewBlob) return;
    const url = URL.createObjectURL(currentPreviewBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = currentPreviewName;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Download started', 'success');
}

function closePreview() {
    document.getElementById('previewCard').style.display = 'none';
    document.getElementById('previewContent').innerHTML = '';
    currentPreviewBlob = null;
    currentPreviewName = '';
}

// ─── Files: Delete ───
async function doDelete(fileId) {
    requireAuth();
    if (!confirm('Delete file ' + fileId + '?')) return;

    try {
        const start = Date.now();
        await wfx.deleteFile(fileId);
        const elapsed = Date.now() - start;

        addLog('DELETE', `/api/v1/files/${fileId}`, 200, elapsed, null, { status: 'deleted' });
        showToast('File deleted', 'success');
        doListFiles(); // refresh
    } catch (e) {
        addLog('DELETE', `/api/v1/files/${fileId}`, e.statusCode || 500, 0, null, { error: e.message });
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
        const start = Date.now();
        const resp = await wfx.serverEncrypt(message, { layer });
        const elapsed = Date.now() - start;

        lastEncryptedMsg = resp;
        document.getElementById('decryptMsgBtn').disabled = false;

        addLog('POST', '/api/v1/messages/encrypt', 200, elapsed, { message, layer }, resp);
        showResult('msgEncResult', JSON.stringify(resp, null, 2));
        clearBusy();
        showToast('Message encrypted via SDK!', 'success');
    } catch (e) {
        clearBusy();
        addLog('POST', '/api/v1/messages/encrypt', e.statusCode || 500, 0, null, { error: e.message });
        showResult('msgEncResult', e.message, true);
    }
}

// ─── Messages: Server Decrypt ───
async function doMsgDecrypt() {
    requireAuth();
    if (!lastEncryptedMsg) return alert('Encrypt a message first');

    setBusy('Decrypting...');
    try {
        const start = Date.now();
        const decryptedText = await wfx.serverDecrypt({
            encryptedMessage: lastEncryptedMsg.encrypted_message,
            nonce: lastEncryptedMsg.nonce,
            keyPartA: lastEncryptedMsg.key_part_a,
            messageTag: lastEncryptedMsg.message_tag || '',
        });
        const elapsed = Date.now() - start;

        addLog('POST', '/api/v1/messages/decrypt', 200, elapsed, null, { message: decryptedText });
        showResult('msgDecResult', '✅ Decrypted: ' + decryptedText);
        clearBusy();
    } catch (e) {
        clearBusy();
        addLog('POST', '/api/v1/messages/decrypt', e.statusCode || 500, 0, null, { error: e.message });
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
        const start = Date.now();
        const resp = await wfx.serverEncryptBatch(messages, { layer: 4 });
        const elapsed = Date.now() - start;

        addLog('POST', '/api/v1/messages/batch/encrypt', 200, elapsed, { count: messages.length }, resp);
        showResult('batchResult', JSON.stringify(resp, null, 2));
        clearBusy();
        showToast(`${messages.length} messages encrypted via SDK!`, 'success');
    } catch (e) {
        clearBusy();
        addLog('POST', '/api/v1/messages/batch/encrypt', e.statusCode || 500, 0, null, { error: e.message });
        showResult('batchResult', e.message, true);
    }
}

// ═══════════════════════════════════════════════════════════
// UI Helpers
// ═══════════════════════════════════════════════════════════

function requireSDK() {
    if (!wfx) {
        showToast('Please connect to server first', 'error');
        throw new Error('Not connected');
    }
}

function requireAuth() {
    requireSDK();
    if (!wfx.isAuthenticated()) {
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
