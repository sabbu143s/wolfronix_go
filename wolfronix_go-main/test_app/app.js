// ═══════════════════════════════════════════════════════════
//  Wolfronix Secure Vault — Application Logic
// ═══════════════════════════════════════════════════════════

let wfx = null;
let currentRecipient = null;
let currentUserId = null;
let chatMessages = {};  // { recipientId: [{ type, text, packet, time }] }
let chatPollTimer = null;
const RELAY_URL = window.location.origin;

// ──────────────────────────────────────────────────────────
//  INIT & CONNECTION
// ──────────────────────────────────────────────────────────

function initClient() {
    try {
        wfx = new WolfronixSDK.default({
            baseUrl: 'https://49.206.202.13:9443/',
            clientId: 'wolfronix_client_1',
            wolfronixKey: 'c07836e1f33c9d1ccdd099e26643e9fc5449c2a490380fef5b446b208c10eda6',
            insecure: true,
            timeout: 30000,
            retries: 3
        });

        // Health check
        wfx.healthCheck().then(ok => {
            if (ok) {
                setBadge('connected', 'Connected');
                showToast('Connected to Wolfronix server', 'success');
                addLog('GET', '/health', 200, 'Server is healthy');
            } else {
                setBadge('degraded', 'Degraded');
                showToast('Server reachable but health check returned false', 'error');
            }
        }).catch(err => {
            // Still create the client even if health fails
            setBadge('degraded', 'Offline Mode');
            showToast('Connected (server may be unreachable): ' + err.message, 'error');
        });
    } catch (err) {
        showToast('Failed to init: ' + err.message, 'error');
    }
}

// ──────────────────────────────────────────────────────────
//  AUTHENTICATION
// ──────────────────────────────────────────────────────────

async function doRegister() {
    if (!wfx) return showToast('Connect to server first', 'error');
    const email = document.getElementById('regEmail').value.trim();
    const pass = document.getElementById('regPassword').value;
    if (!email || !pass) return showToast('Enter email and password', 'error');

    try {
        showToast('Generating RSA keys...', 'success');
        const res = await wfx.register(email, pass);
        addLog('POST', '/api/v1/users/register', 200, JSON.stringify(res));
        showToast('Registered! User: ' + res.user_id, 'success');
        showUserInfo(email);
    } catch (err) {
        showToast('Register failed: ' + err.message, 'error');
        addLog('POST', '/api/v1/users/register', err.statusCode || 500, err.message);
    }
}

async function doLogin() {
    if (!wfx) return showToast('Connect to server first', 'error');
    const email = document.getElementById('loginEmail').value.trim();
    const pass = document.getElementById('loginPassword').value;
    if (!email || !pass) return showToast('Enter email and password', 'error');

    try {
        showToast('Fetching & unwrapping keys...', 'success');
        const res = await wfx.login(email, pass);
        addLog('POST', '/api/v1/users/login', 200, JSON.stringify(res));
        showToast('Logged in! Welcome back.', 'success');
        showUserInfo(email);
    } catch (err) {
        showToast('Login failed: ' + err.message, 'error');
        addLog('POST', '/api/v1/users/login', err.statusCode || 500, err.message);
    }
}

function doLogout() {
    if (wfx) wfx.logout();
    currentUserId = null;
    stopChatPoll();
    document.getElementById('user-info').style.display = 'none';
    document.getElementById('user-badge').style.display = 'none';
    showToast('Logged out. Keys cleared.', 'success');
}

function showUserInfo(email) {
    currentUserId = email;
    document.getElementById('user-info').style.display = 'block';
    document.getElementById('currentUser').textContent = email;
    document.getElementById('keyStatus').textContent = wfx.hasPrivateKey() ? '🔑 RSA-2048 keys loaded' : '⚠️ No private key';
    document.getElementById('userAvatar').textContent = email.charAt(0).toUpperCase();
    document.getElementById('user-badge').style.display = 'flex';
    document.getElementById('userBadgeName').textContent = email.split('@')[0];
    startChatPoll();
}

// ──────────────────────────────────────────────────────────
//  IDENTITY VAULT — Aadhaar
// ──────────────────────────────────────────────────────────

async function saveAadhaar() {
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');

    const data = {
        type: 'aadhaar',
        number: document.getElementById('aadhaarNumber').value.trim(),
        name: document.getElementById('aadhaarName').value.trim(),
        dob: document.getElementById('aadhaarDob').value,
        gender: document.getElementById('aadhaarGender').value,
        address: document.getElementById('aadhaarAddress').value.trim()
    };

    if (!data.number || !data.name) return showToast('Aadhaar number and name are required', 'error');

    try {
        showToast('Encrypting Aadhaar data...', 'success');

        // Encrypt JSON data as a blob
        const jsonBlob = new Blob([JSON.stringify(data)], { type: 'application/json' });
        const res = await wfx.encrypt(jsonBlob, 'aadhaar_' + maskAadhaar(data.number) + '.json');
        addLog('POST', '/api/v1/encrypt', 200, JSON.stringify(res));
        showToast('Aadhaar encrypted & stored! ID: ' + res.file_id, 'success');

        // Also upload the scan if provided
        const fileInput = document.getElementById('aadhaarFile');
        if (fileInput.files.length > 0) {
            showToast('Encrypting Aadhaar scan...', 'success');
            const scanRes = await wfx.encrypt(fileInput.files[0], 'aadhaar_scan_' + maskAadhaar(data.number) + '.' + getExtension(fileInput.files[0].name));
            addLog('POST', '/api/v1/encrypt', 200, JSON.stringify(scanRes));
            showToast('Aadhaar scan encrypted! ID: ' + scanRes.file_id, 'success');
        }

        // Clear form
        document.getElementById('aadhaarNumber').value = '';
        document.getElementById('aadhaarName').value = '';
        document.getElementById('aadhaarDob').value = '';
        document.getElementById('aadhaarGender').value = '';
        document.getElementById('aadhaarAddress').value = '';
        fileInput.value = '';

        loadIdentityDocs();
    } catch (err) {
        showToast('Failed: ' + err.message, 'error');
    }
}

// ──────────────────────────────────────────────────────────
//  IDENTITY VAULT — PAN
// ──────────────────────────────────────────────────────────

async function savePAN() {
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');

    const data = {
        type: 'pan',
        number: document.getElementById('panNumber').value.trim(),
        name: document.getElementById('panName').value.trim(),
        dob: document.getElementById('panDob').value,
        father: document.getElementById('panFather').value.trim()
    };

    if (!data.number || !data.name) return showToast('PAN number and name are required', 'error');

    try {
        showToast('Encrypting PAN data...', 'success');

        const jsonBlob = new Blob([JSON.stringify(data)], { type: 'application/json' });
        const res = await wfx.encrypt(jsonBlob, 'pan_' + data.number.slice(-4) + '.json');
        addLog('POST', '/api/v1/encrypt', 200, JSON.stringify(res));
        showToast('PAN encrypted & stored! ID: ' + res.file_id, 'success');

        // Upload scan if provided
        const fileInput = document.getElementById('panFile');
        if (fileInput.files.length > 0) {
            showToast('Encrypting PAN scan...', 'success');
            const scanRes = await wfx.encrypt(fileInput.files[0], 'pan_scan_' + data.number.slice(-4) + '.' + getExtension(fileInput.files[0].name));
            addLog('POST', '/api/v1/encrypt', 200, JSON.stringify(scanRes));
            showToast('PAN scan encrypted! ID: ' + scanRes.file_id, 'success');
        }

        // Clear form
        document.getElementById('panNumber').value = '';
        document.getElementById('panName').value = '';
        document.getElementById('panDob').value = '';
        document.getElementById('panFather').value = '';
        fileInput.value = '';

        loadIdentityDocs();
    } catch (err) {
        showToast('Failed: ' + err.message, 'error');
    }
}

// ──────────────────────────────────────────────────────────
//  IDENTITY VAULT — Load Documents
// ──────────────────────────────────────────────────────────

async function loadIdentityDocs() {
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');

    try {
        const { files } = await wfx.listFiles();
        const container = document.getElementById('identityDocsList');
        const identityFiles = files.filter(f =>
            f.original_name.startsWith('aadhaar_') || f.original_name.startsWith('pan_')
        );

        if (identityFiles.length === 0) {
            container.innerHTML = '<p class="placeholder">No identity documents found. Save an Aadhaar or PAN above.</p>';
            return;
        }

        container.innerHTML = identityFiles.map(f => {
            const isAadhaar = f.original_name.startsWith('aadhaar_');
            const isScan = f.original_name.includes('_scan_');
            const icon = isAadhaar ? '🇮🇳' : '🏛️';
            const label = isAadhaar ? 'Aadhaar' : 'PAN';
            const iconClass = isAadhaar ? 'aadhaar' : 'pan';

            return `<div class="vault-item">
                <div class="vault-item-icon ${iconClass}">${icon}</div>
                <div class="vault-item-info">
                    <div class="item-name">${escapeHtml(label + (isScan ? ' Scan' : ' Data'))}</div>
                    <div class="item-meta">${escapeHtml(f.original_name)} · ${formatBytes(f.encrypted_size)} · ${formatDate(f.created_at)}</div>
                </div>
                <div class="vault-item-actions">
                    <button class="btn-view" onclick="viewIdentityDoc('${escapeHtml(f.file_id)}', '${escapeHtml(f.original_name)}')">🔓 View</button>
                    <button class="btn-delete" onclick="deleteVaultItem('${escapeHtml(f.file_id)}', 'identity')">🗑️</button>
                </div>
            </div>`;
        }).join('');
    } catch (err) {
        showToast('Failed to load: ' + err.message, 'error');
    }
}

async function viewIdentityDoc(fileId, filename) {
    if (!wfx) return;

    try {
        showToast('Decrypting document...', 'success');

        if (filename.includes('_scan_')) {
            // It's an image/PDF scan — decrypt and preview
            const blob = await wfx.decrypt(fileId);
            const url = URL.createObjectURL(blob);
            const ext = getExtension(filename).toLowerCase();

            const modal = document.getElementById('docViewerModal');
            const title = document.getElementById('docViewerTitle');
            const body = document.getElementById('docViewerBody');

            title.textContent = filename.includes('aadhaar') ? 'Aadhaar Scan' : 'PAN Scan';

            if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) {
                body.innerHTML = `<img src="${url}" style="max-width:100%; border-radius:8px;">`;
            } else if (ext === 'pdf') {
                body.innerHTML = `<iframe src="${url}" style="width:100%; height:500px; border:none;"></iframe>`;
            } else {
                body.innerHTML = `<a href="${url}" download="${escapeHtml(filename)}" class="btn-primary" style="display:inline-block; padding:12px 24px;">⬇ Download File</a>`;
            }

            modal.style.display = 'flex';
        } else {
            // It's JSON data — decrypt and show details
            const buffer = await wfx.decryptToBuffer(fileId);
            const text = new TextDecoder().decode(buffer);
            const data = JSON.parse(text);

            const modal = document.getElementById('docViewerModal');
            const title = document.getElementById('docViewerTitle');
            const body = document.getElementById('docViewerBody');

            if (data.type === 'aadhaar') {
                title.textContent = '🇮🇳 Aadhaar Card Details';
                body.innerHTML = `<div class="doc-detail-grid">
                    <span class="detail-label">Aadhaar No.</span><span class="detail-value masked">${escapeHtml(data.number)}</span>
                    <span class="detail-label">Name</span><span class="detail-value">${escapeHtml(data.name)}</span>
                    <span class="detail-label">Date of Birth</span><span class="detail-value">${escapeHtml(data.dob || '—')}</span>
                    <span class="detail-label">Gender</span><span class="detail-value">${escapeHtml(data.gender || '—')}</span>
                    <span class="detail-label">Address</span><span class="detail-value">${escapeHtml(data.address || '—')}</span>
                </div>`;
            } else if (data.type === 'pan') {
                title.textContent = '🏛️ PAN Card Details';
                body.innerHTML = `<div class="doc-detail-grid">
                    <span class="detail-label">PAN No.</span><span class="detail-value masked">${escapeHtml(data.number)}</span>
                    <span class="detail-label">Name</span><span class="detail-value">${escapeHtml(data.name)}</span>
                    <span class="detail-label">Date of Birth</span><span class="detail-value">${escapeHtml(data.dob || '—')}</span>
                    <span class="detail-label">Father's Name</span><span class="detail-value">${escapeHtml(data.father || '—')}</span>
                </div>`;
            }

            modal.style.display = 'flex';
        }

        showToast('Document decrypted!', 'success');
    } catch (err) {
        showToast('Decrypt failed: ' + err.message, 'error');
    }
}

function closeDocViewer() {
    document.getElementById('docViewerModal').style.display = 'none';
}

// ──────────────────────────────────────────────────────────
//  CARD VAULT
// ──────────────────────────────────────────────────────────

function formatCardNumber(input) {
    let value = input.value.replace(/\D/g, '');
    value = value.replace(/(.{4})/g, '$1 ').trim();
    input.value = value;
    document.getElementById('ccPreviewNumber').textContent = value || '•••• •••• •••• ••••';
}

function formatExpiry(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length >= 2) value = value.slice(0, 2) + '/' + value.slice(2);
    input.value = value;
    document.getElementById('ccPreviewExpiry').textContent = value || 'MM/YY';
}

function formatAadhaar(input) {
    let value = input.value.replace(/\D/g, '');
    value = value.replace(/(.{4})/g, '$1 ').trim();
    input.value = value;
}

function updateCardPreview() {
    document.getElementById('ccPreviewName').textContent =
        document.getElementById('cardName').value.toUpperCase() || 'YOUR NAME';
}

async function saveCard() {
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');

    const data = {
        type: 'card',
        number: document.getElementById('cardNumber').value.replace(/\s/g, ''),
        name: document.getElementById('cardName').value.trim(),
        expiry: document.getElementById('cardExpiry').value.trim(),
        cvv: document.getElementById('cardCvv').value.trim(),
        cardType: document.getElementById('cardType').value,
        bank: document.getElementById('cardBank').value.trim()
    };

    if (!data.number || data.number.length < 12) return showToast('Enter a valid card number', 'error');
    if (!data.name) return showToast('Enter cardholder name', 'error');
    if (!data.expiry) return showToast('Enter expiry date', 'error');

    try {
        showToast('Encrypting card details...', 'success');

        const jsonBlob = new Blob([JSON.stringify(data)], { type: 'application/json' });
        const last4 = data.number.slice(-4);
        const res = await wfx.encrypt(jsonBlob, 'card_' + data.bank.toLowerCase().replace(/\s/g, '_') + '_' + last4 + '.json');
        addLog('POST', '/api/v1/encrypt', 200, JSON.stringify(res));
        showToast('Card encrypted & stored! ID: ' + res.file_id, 'success');

        // Clear form
        document.getElementById('cardNumber').value = '';
        document.getElementById('cardName').value = '';
        document.getElementById('cardExpiry').value = '';
        document.getElementById('cardCvv').value = '';
        document.getElementById('cardBank').value = '';
        document.getElementById('ccPreviewNumber').textContent = '•••• •••• •••• ••••';
        document.getElementById('ccPreviewName').textContent = 'YOUR NAME';
        document.getElementById('ccPreviewExpiry').textContent = 'MM/YY';

        loadCards();
    } catch (err) {
        showToast('Failed: ' + err.message, 'error');
    }
}

async function loadCards() {
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');

    try {
        const { files } = await wfx.listFiles();
        const container = document.getElementById('cardsList');
        const cardFiles = files.filter(f => f.original_name.startsWith('card_'));

        if (cardFiles.length === 0) {
            container.innerHTML = '<p class="placeholder">No cards saved yet. Add a card above.</p>';
            return;
        }

        container.innerHTML = cardFiles.map(f => {
            const parts = f.original_name.replace('.json', '').split('_');
            const last4 = parts[parts.length - 1];
            const bank = parts.slice(1, -1).join(' ');

            return `<div class="vault-item">
                <div class="vault-item-icon card">💳</div>
                <div class="vault-item-info">
                    <div class="item-name">•••• •••• •••• ${escapeHtml(last4)}</div>
                    <div class="item-meta">${escapeHtml(bank.toUpperCase())} · ${formatDate(f.created_at)}</div>
                </div>
                <div class="vault-item-actions">
                    <button class="btn-view" onclick="viewCard('${escapeHtml(f.file_id)}')">🔓 View</button>
                    <button class="btn-delete" onclick="deleteVaultItem('${escapeHtml(f.file_id)}', 'cards')">🗑️</button>
                </div>
            </div>`;
        }).join('');
    } catch (err) {
        showToast('Failed to load: ' + err.message, 'error');
    }
}

async function viewCard(fileId) {
    if (!wfx) return;

    try {
        showToast('Decrypting card...', 'success');
        const buffer = await wfx.decryptToBuffer(fileId);
        const text = new TextDecoder().decode(buffer);
        const data = JSON.parse(text);

        const modal = document.getElementById('docViewerModal');
        const title = document.getElementById('docViewerTitle');
        const body = document.getElementById('docViewerBody');

        const formatted = data.number.replace(/(.{4})/g, '$1 ').trim();
        title.textContent = '💳 Card Details';
        body.innerHTML = `<div class="doc-detail-grid">
            <span class="detail-label">Card Number</span><span class="detail-value masked">${escapeHtml(formatted)}</span>
            <span class="detail-label">Cardholder</span><span class="detail-value">${escapeHtml(data.name)}</span>
            <span class="detail-label">Expiry</span><span class="detail-value">${escapeHtml(data.expiry)}</span>
            <span class="detail-label">CVV</span><span class="detail-value masked">${escapeHtml(data.cvv)}</span>
            <span class="detail-label">Type</span><span class="detail-value">${escapeHtml(data.cardType || '—')}</span>
            <span class="detail-label">Bank</span><span class="detail-value">${escapeHtml(data.bank || '—')}</span>
        </div>`;

        modal.style.display = 'flex';
        showToast('Card decrypted!', 'success');
    } catch (err) {
        showToast('Decrypt failed: ' + err.message, 'error');
    }
}

// ──────────────────────────────────────────────────────────
//  FILE VAULT
// ──────────────────────────────────────────────────────────

function handleDrop(e) {
    e.preventDefault();
    document.getElementById('uploadZone').classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        document.getElementById('fileInput').files = e.dataTransfer.files;
        onFileSelected(document.getElementById('fileInput'));
    }
}

function onFileSelected(input) {
    const file = input.files[0];
    if (file) {
        document.getElementById('selectedFileName').textContent = file.name + ' (' + formatBytes(file.size) + ')';
        document.getElementById('encryptBtn').disabled = false;
    }
}

async function doEncrypt() {
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');
    const file = document.getElementById('fileInput').files[0];
    if (!file) return showToast('Select a file', 'error');

    try {
        document.getElementById('encryptBtn').disabled = true;
        showToast('Encrypting ' + file.name + '...', 'success');
        const res = await wfx.encrypt(file);
        const el = document.getElementById('encryptResult');
        el.style.display = 'block';
        el.className = 'result-box success';
        el.textContent = JSON.stringify(res, null, 2);
        addLog('POST', '/api/v1/encrypt', 200, JSON.stringify(res));
        showToast('Encrypted! File ID: ' + res.file_id, 'success');
        doListFiles();
    } catch (err) {
        const el = document.getElementById('encryptResult');
        el.style.display = 'block';
        el.className = 'result-box error';
        el.textContent = err.message;
        showToast('Encrypt failed: ' + err.message, 'error');
    } finally {
        document.getElementById('encryptBtn').disabled = false;
    }
}

async function doListFiles() {
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');

    try {
        const { files } = await wfx.listFiles();
        const container = document.getElementById('fileList');

        // Filter out vault items (identity, card data) — show only generic files
        const generalFiles = files.filter(f =>
            !f.original_name.startsWith('aadhaar_') &&
            !f.original_name.startsWith('pan_') &&
            !f.original_name.startsWith('card_')
        );

        if (generalFiles.length === 0) {
            container.innerHTML = '<p class="placeholder">No files yet. Upload one above.</p>';
            return;
        }

        container.innerHTML = generalFiles.map(f => `
            <div class="vault-item">
                <div class="vault-item-icon file">📄</div>
                <div class="vault-item-info">
                    <div class="item-name">${escapeHtml(f.original_name)}</div>
                    <div class="item-meta">ID: ${escapeHtml(f.file_id)} · ${formatBytes(f.encrypted_size)} · ${formatDate(f.created_at)}</div>
                </div>
                <div class="vault-item-actions">
                    <button class="btn-view" onclick="doDecryptById('${escapeHtml(f.file_id)}', '${escapeHtml(f.original_name)}')">🔓 Decrypt</button>
                    <button class="btn-delete" onclick="deleteVaultItem('${escapeHtml(f.file_id)}', 'files')">🗑️</button>
                </div>
            </div>
        `).join('');

        addLog('GET', '/api/v1/files', 200, files.length + ' files');
    } catch (err) {
        showToast('Failed to list: ' + err.message, 'error');
    }
}

async function doDecrypt() {
    const fid = document.getElementById('decryptFileId').value.trim();
    if (!fid) return showToast('Enter a File ID', 'error');
    await doDecryptById(fid, 'decrypted_file');
}

async function doDecryptById(fileId, filename) {
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');

    try {
        showToast('Decrypting...', 'success');
        const blob = await wfx.decrypt(fileId);
        addLog('POST', '/api/v1/files/' + fileId + '/decrypt', 200, formatBytes(blob.size));

        // Preview
        showPreview(blob, filename);
        showToast('File decrypted!', 'success');
    } catch (err) {
        showToast('Decrypt failed: ' + err.message, 'error');
    }
}

let currentPreviewBlob = null;
let currentPreviewName = '';

function showPreview(blob, filename) {
    currentPreviewBlob = blob;
    currentPreviewName = filename;

    const card = document.getElementById('previewCard');
    const content = document.getElementById('previewContent');
    const title = document.getElementById('previewTitle');

    card.style.display = 'block';
    title.textContent = filename;

    const type = blob.type || '';
    const ext = getExtension(filename).toLowerCase();

    if (type.startsWith('text/') || ['txt', 'json', 'csv', 'xml', 'html', 'css', 'js', 'md', 'log'].includes(ext)) {
        blob.text().then(t => {
            content.innerHTML = `<pre class="preview-text">${escapeHtml(t)}</pre>`;
        });
    } else if (type.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(ext)) {
        const url = URL.createObjectURL(blob);
        content.innerHTML = `<img class="preview-image" src="${url}" alt="${escapeHtml(filename)}">`;
    } else if (type === 'application/pdf' || ext === 'pdf') {
        const url = URL.createObjectURL(blob);
        content.innerHTML = `<iframe class="preview-pdf" src="${url}"></iframe>`;
    } else if (type.startsWith('video/') || ['mp4', 'webm', 'ogg'].includes(ext)) {
        const url = URL.createObjectURL(blob);
        content.innerHTML = `<video class="preview-video" controls src="${url}"></video>`;
    } else if (type.startsWith('audio/') || ['mp3', 'wav', 'ogg', 'flac'].includes(ext)) {
        const url = URL.createObjectURL(blob);
        content.innerHTML = `<audio class="preview-audio" controls src="${url}"></audio>`;
    } else {
        content.innerHTML = `<div class="preview-binary">
            <div class="preview-binary-icon">📦</div>
            <div>${escapeHtml(filename)}</div>
            <div class="preview-binary-type">${escapeHtml(type || 'Unknown type')} · ${formatBytes(blob.size)}</div>
            <button onclick="downloadPreview()" class="btn-primary" style="margin-top:12px;">⬇ Download</button>
        </div>`;
    }
}

function downloadPreview() {
    if (!currentPreviewBlob) return;
    const url = URL.createObjectURL(currentPreviewBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = currentPreviewName;
    a.click();
    URL.revokeObjectURL(url);
}

function closePreview() {
    document.getElementById('previewCard').style.display = 'none';
}

// ──────────────────────────────────────────────────────────
//  SHARED — Delete vault item
// ──────────────────────────────────────────────────────────

async function deleteVaultItem(fileId, reloadType) {
    if (!wfx) return;
    if (!confirm('Delete this encrypted item permanently?')) return;

    try {
        await wfx.deleteFile(fileId);
        showToast('Deleted!', 'success');
        addLog('DELETE', '/api/v1/files/' + fileId, 200, 'Deleted');

        if (reloadType === 'identity') loadIdentityDocs();
        else if (reloadType === 'cards') loadCards();
        else if (reloadType === 'files') doListFiles();
    } catch (err) {
        showToast('Delete failed: ' + err.message, 'error');
    }
}

// ──────────────────────────────────────────────────────────
//  SECURE CHAT (E2E)
// ──────────────────────────────────────────────────────────

function startChat() {
    const recipientId = document.getElementById('chatRecipientId').value.trim();
    if (!recipientId) return showToast('Enter recipient user ID', 'error');
    if (!wfx || !wfx.isAuthenticated()) return showToast('Login first', 'error');

    currentRecipient = recipientId;

    // Add to contacts if not exists
    if (!chatMessages[recipientId]) {
        chatMessages[recipientId] = [];
    }

    // Update UI
    document.getElementById('chatHeader').style.display = 'block';
    document.getElementById('chatInputBar').style.display = 'flex';
    document.getElementById('chatRecipientName').textContent = recipientId;
    document.getElementById('chatAvatar').textContent = recipientId.charAt(0).toUpperCase();

    renderChatContacts();
    renderChatMessages();

    showToast('Chat opened with ' + recipientId, 'success');
}

function switchChat(recipientId) {
    currentRecipient = recipientId;
    document.getElementById('chatRecipientId').value = recipientId;
    document.getElementById('chatRecipientName').textContent = recipientId;
    document.getElementById('chatAvatar').textContent = recipientId.charAt(0).toUpperCase();
    document.getElementById('chatInputBar').style.display = 'flex';
    renderChatContacts();
    renderChatMessages();
}

async function sendChatMessage() {
    if (!wfx || !currentRecipient) return;
    const input = document.getElementById('chatMessageInput');
    const text = input.value.trim();
    if (!text) return;

    input.value = '';

    try {
        // Encrypt message using E2E encryption
        const packet = await wfx.encryptMessage(text, currentRecipient);
        addLog('POST', '/api/v1/messages/encrypt', 200, 'E2E encrypted');

        // Relay the encrypted packet to the server for delivery
        try {
            await fetch(RELAY_URL + '/api/chat/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ to: currentRecipient, from: currentUserId, packet })
            });
            addLog('POST', '/api/chat/send', 200, 'Relayed to ' + currentRecipient);
        } catch (relayErr) {
            console.warn('Relay failed (message encrypted locally):', relayErr);
        }

        // Store in chat history
        chatMessages[currentRecipient].push({
            type: 'sent',
            text: text,
            packet: packet,
            time: new Date().toISOString()
        });

        renderChatMessages();
        renderChatContacts();
    } catch (err) {
        showToast('Encrypt failed: ' + err.message, 'error');
        addLog('POST', '/api/v1/messages/encrypt', 500, err.message);
    }
}

// ──────────────────────────────────────────────────────────
//  CHAT POLLING — Auto-receive messages from relay server
// ──────────────────────────────────────────────────────────

function startChatPoll() {
    stopChatPoll();
    chatPollTimer = setInterval(pollForMessages, 2000);
}

function stopChatPoll() {
    if (chatPollTimer) {
        clearInterval(chatPollTimer);
        chatPollTimer = null;
    }
}

async function pollForMessages() {
    if (!currentUserId || !wfx || !wfx.isAuthenticated()) return;

    try {
        const res = await fetch(RELAY_URL + '/api/chat/messages?userId=' + encodeURIComponent(currentUserId));
        const { messages } = await res.json();

        if (!messages || messages.length === 0) return;

        for (const msg of messages) {
            const senderId = msg.from;

            // Ensure conversation exists
            if (!chatMessages[senderId]) chatMessages[senderId] = [];

            // Auto-decrypt everything immediately
            let decryptedText = null;
            try {
                decryptedText = await wfx.decryptMessage(msg.packet);
            } catch (e) {
                console.warn('Auto-decrypt failed for', senderId, ':', e.message);
            }

            if (decryptedText) {
                // Check if decrypted content is media (JSON with base64 data)
                let isMedia = false;
                try {
                    const mediaCheck = JSON.parse(decryptedText);
                    if ((mediaCheck.mediaType === 'file' && mediaCheck.data) || mediaCheck.mediaType === 'hybrid') {
                        chatMessages[senderId].push({
                            type: 'received',
                            text: '📎 ' + mediaCheck.fileName,
                            isMedia: true,
                            media: mediaCheck,
                            packet: msg.packet,
                            time: new Date(msg.timestamp).toISOString()
                        });
                        isMedia = true;
                    }
                } catch (e) { /* not media JSON */ }

                if (!isMedia) {
                    chatMessages[senderId].push({
                        type: 'received',
                        text: decryptedText,
                        decryptedText: decryptedText,
                        packet: msg.packet,
                        time: new Date(msg.timestamp).toISOString()
                    });
                }
            } else {
                // Decrypt failed — store raw (will show as error)
                chatMessages[senderId].push({
                    type: 'received',
                    text: null,
                    decryptedText: null,
                    packet: msg.packet,
                    time: new Date(msg.timestamp).toISOString()
                });
            }

            // Notify if not currently viewing this chat
            if (senderId !== currentRecipient) {
                showToast('💬 New message from ' + senderId, 'success');
            }
        }

        renderChatContacts();
        if (currentRecipient && chatMessages[currentRecipient]) {
            renderChatMessages();
        }
    } catch (e) {
        // Silently fail — relay might not be running
    }
}

async function decryptReceivedMessage(recipientId, index) {
    const msg = chatMessages[recipientId][index];
    if (!msg || !msg.packet) return;

    try {
        const plainText = await wfx.decryptMessage(msg.packet);

        // Check if decrypted content is a media payload (not plain text)
        try {
            const mediaCheck = JSON.parse(plainText);
            if (mediaCheck.mediaType === 'file' && mediaCheck.data) {
                msg.isMedia = true;
                msg.media = mediaCheck;
                msg.text = '📎 ' + mediaCheck.fileName;
                renderChatMessages();
                showToast('Media decrypted! Tap to view.', 'success');
                return;
            }
        } catch (e) { /* not media JSON, it's regular text */ }

        msg.decryptedText = plainText;
        renderChatMessages();
        showToast('Message decrypted!', 'success');
    } catch (err) {
        showToast('Decrypt failed: ' + err.message, 'error');
    }
}

function simulateReceiveMessage() {
    if (!currentRecipient) return showToast('Open a chat first', 'error');

    const packet = prompt('Paste the encrypted packet (JSON string) from the sender:');
    if (!packet) return;

    chatMessages[currentRecipient].push({
        type: 'received',
        text: null,
        packet: packet,
        time: new Date().toISOString()
    });

    renderChatMessages();
    renderChatContacts();
    showToast('Encrypted message received!', 'success');
}

function copyPacket(index) {
    if (!currentRecipient || !chatMessages[currentRecipient]) return;
    const msg = chatMessages[currentRecipient][index];
    if (!msg || !msg.packet) return;

    navigator.clipboard.writeText(msg.packet).then(() => {
        showToast('Encrypted packet copied! Paste it in the other browser.', 'success');
    }).catch(() => {
        // Fallback for non-HTTPS
        const ta = document.createElement('textarea');
        ta.value = msg.packet;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Encrypted packet copied!', 'success');
    });
}

function renderChatContacts() {
    const container = document.getElementById('chatContacts');
    const ids = Object.keys(chatMessages);

    if (ids.length === 0) {
        container.innerHTML = '<p class="placeholder" style="padding:12px; font-size:12px;">No conversations yet</p>';
        return;
    }

    container.innerHTML = ids.map(id => {
        const msgs = chatMessages[id];
        const lastMsg = msgs.length > 0 ? msgs[msgs.length - 1] : null;
        const lastText = lastMsg ? (lastMsg.text || '🔒 Encrypted message') : 'No messages';
        const isActive = id === currentRecipient;

        return `<div class="chat-contact ${isActive ? 'active' : ''}" onclick="switchChat('${escapeHtml(id)}')">
            <div class="chat-contact-avatar">${id.charAt(0).toUpperCase()}</div>
            <div>
                <div class="chat-contact-name">${escapeHtml(id)}</div>
                <div class="chat-contact-last">${escapeHtml(lastText.slice(0, 30))}</div>
            </div>
        </div>`;
    }).join('');
}

// ──────────────────────────────────────────────────────────
//  CHAT MEDIA — E2E encrypted file sharing
// ──────────────────────────────────────────────────────────

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}
function base64ToBlob(base64, mimeType) {
    const byteChars = atob(base64);
    const byteArrays = [];
    for (let offset = 0; offset < byteChars.length; offset += 512) {
        const slice = byteChars.slice(offset, offset + 512);
        const byteNumbers = new Array(slice.length);
        for (let i = 0; i < slice.length; i++) byteNumbers[i] = slice.charCodeAt(i);
        byteArrays.push(new Uint8Array(byteNumbers));
    }
    return new Blob(byteArrays, { type: mimeType });
}
function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Limit the legacy E2E data payload size, but allow up to 1GB for hybrid upload
const MAX_HYBRID_SIZE = 1000 * 1024 * 1024; // 1GB limit for vault upload

async function sendChatMedia(fileInput) {
    if (!wfx || !wfx.isAuthenticated() || !currentRecipient) {
        showToast('Login and open a chat first', 'error');
        return;
    }

    const file = fileInput.files[0];
    if (!file) return;
    fileInput.value = '';

    if (file.size > MAX_HYBRID_SIZE) {
        showToast('File too large. Max: 1 GB', 'error');
        return;
    }

    try {
        let mediaPayload;
        
        // Use true Hybrid E2E for files 
        // 1. Upload file securely to the vault (streams without memory crash)
        showToast('Encrypting & uploading ' + file.name + ' to vault...', 'success');
        const res = await wfx.encrypt(file);
        const fileId = res.file_id;
        addLog('POST', '/api/v1/encrypt', 200, 'Vault upload complete: ' + fileId);

        showToast('Preparing hybrid key exchange...', 'success');

        // 2. Fetch the RSA-encrypted Key_Part_A for this file
        const keyRes = await wfx.getFileKey(fileId);
        
        // 3. Decrypt Key_Part_A using our local private key
        const encryptedKeyBuffer = base64ToArrayBuffer(keyRes.key_part_a);
        const rawKeyBuffer = await window.crypto.subtle.decrypt({name: "RSA-OAEP"}, wfx.privateKey, encryptedKeyBuffer);
        const rawKeyB64 = arrayBufferToBase64(rawKeyBuffer);

        // 4. Build hybrid media payload (NO base64 file data, only the key + id)
        mediaPayload = JSON.stringify({
            mediaType: 'hybrid',
            fileId: fileId,
            rawKeyA: rawKeyB64,
            fileName: file.name,
            fileSize: file.size,
            mimeType: file.type || 'application/octet-stream'
        });

        // 5. E2E encrypt the tiny payload for the recipient
        const encryptedPacket = await wfx.encryptMessage(mediaPayload, currentRecipient);
        addLog('POST', '/api/v1/messages/encrypt', 200, 'Hybrid E2E payload encrypted');

        // 6. Relay the encrypted packet
        try {
            await fetch(RELAY_URL + '/api/chat/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    to: currentRecipient,
                    from: currentUserId,
                    packet: encryptedPacket,
                    isMedia: true,
                    mediaInfo: { fileName: file.name, fileSize: file.size, mimeType: file.type, isHybrid: true }
                })
            });
            addLog('POST', '/api/chat/send', 200, 'E2E media relayed: ' + file.name);
        } catch (relayErr) {
            console.warn('Media relay failed:', relayErr);
        }

        // 7. Store in local chat history (sender keeps own copy state)
        if (!chatMessages[currentRecipient]) chatMessages[currentRecipient] = [];
        chatMessages[currentRecipient].push({
            type: 'sent',
            text: '📎 ' + file.name,
            isMedia: true,
            media: {
                mediaType: 'hybrid',
                fileId: fileId,
                rawKeyA: rawKeyB64,
                fileName: file.name,
                fileSize: file.size,
                mimeType: file.type || 'application/octet-stream',
            },
            packet: encryptedPacket,
            time: new Date().toISOString()
        });

        renderChatMessages();
        renderChatContacts();
        showToast('E2E media sent! ' + file.name, 'success');

    } catch (err) {
        showToast('Media send failed: ' + err.message, 'error');
    }
}

function getMediaIcon(mimeType) {
    if (!mimeType) return '📄';
    if (mimeType.startsWith('image/')) return '🖼️';
    if (mimeType.startsWith('video/')) return '🎬';
    if (mimeType.startsWith('audio/')) return '🎵';
    if (mimeType.includes('pdf')) return '📕';
    if (mimeType.includes('word') || mimeType.includes('document')) return '📝';
    return '📄';
}

async function downloadHybridMedia(index, bubbleId, role = "shared") {
    const container = document.getElementById(bubbleId);
    if (!container || !currentRecipient) return;

    const msg = chatMessages[currentRecipient][index];
    if (!msg || !msg.media) return;

    try {
        container.innerHTML = '<div class="media-uploading">⬇️ Downloading & Decrypting securely...</div>';
        
        let blob;
        if (role === "owner") {
            // Sender can just use default vault download
            blob = await wfx.decrypt(msg.media.fileId, "owner");
        } else {
            // Recipient uses the hybrid E2E shared key
            blob = await wfx.request("POST", `/api/v1/files/${msg.media.fileId}/decrypt`, {
                responseType: "blob",
                body: {
                    decrypted_key_a: msg.media.rawKeyA,
                    user_role: "shared"
                }
            });
        }

        const url = URL.createObjectURL(blob);
        msg.media.blobUrl = url; // Save so it auto-renders inline on next render

        renderChatMessages();

        // If it's a generic file, force download
        const mime = msg.media.mimeType || '';
        if (!mime.startsWith('image/') && !mime.startsWith('video/') && !mime.startsWith('audio/')) {
            const a = document.createElement('a');
            a.href = url;
            a.download = msg.media.fileName;
            a.click();
        }

        showToast('File downloaded successfully!', 'success');
    } catch (err) {
        container.innerHTML = `<div class="media-uploading" style="color:var(--red);">❌ ${escapeHtml(err.message)}</div>`;
    }
}

function renderMediaBubble(msg, index, bubbleId) {
    // Fallback for media that wasn't auto-decrypted
    const media = msg.media || {};
    const icon = getMediaIcon(media.mimeType || '');
    const name = media.fileName || 'Encrypted media';
    const size = media.fileSize ? formatBytes(media.fileSize) : '—';

    return `<div class="media-bubble-content" id="${bubbleId}">
        <div class="media-file-card" onclick="decryptAndShowMedia(${index}, '${bubbleId}')">
            <div class="media-file-icon">${icon}</div>
            <div class="media-file-info">
                <div class="media-file-name">${escapeHtml(name)}</div>
                <div class="media-file-size">${size} · 🔓 Tap to decrypt & view</div>
            </div>
        </div>
    </div>`;
}

function renderAutoMedia(media, bubbleId, index, isSender = false) {
    if (!media) return `<div class="media-bubble-content" id="${bubbleId}"><em>No data</em></div>`;

    if (media.mediaType === 'hybrid') {
        const icon = getMediaIcon(media.mimeType);
        
        // If downloaded locally
        if (media.blobUrl) {
           const mime = media.mimeType || '';
           if (mime.startsWith('image/')) {
               return `<div class="media-bubble-content" id="${bubbleId}">
                   <img src="${media.blobUrl}" alt="${escapeHtml(media.fileName)}" style="max-width:100%; border-radius:8px; cursor:pointer;" onclick="window.open('${media.blobUrl}')">
               </div>`;
           }
           if (mime.startsWith('video/')) {
               return `<div class="media-bubble-content" id="${bubbleId}">
                   <video controls src="${media.blobUrl}" style="max-width:100%; border-radius:8px;"></video>
               </div>`;
           }
           if (mime.startsWith('audio/')) {
               return `<div class="media-bubble-content" id="${bubbleId}">
                   <audio controls src="${media.blobUrl}" style="width:100%;"></audio>
               </div>`;
           }
           return `<div class="media-bubble-content" id="${bubbleId}">
               <div class="media-file-card">
                   <div class="media-file-icon">✅</div>
                   <div class="media-file-info">
                       <div class="media-file-name">${escapeHtml(media.fileName)}</div>
                       <div class="media-file-size">Downloaded</div>
                   </div>
               </div>
           </div>`;
        }

        // Pending download card
        const roleArg = isSender ? `'owner'` : `'shared'`;
        
        return `<div class="media-bubble-content" id="${bubbleId}">
            <div class="media-file-card" onclick="downloadHybridMedia(${index}, '${bubbleId}', ${roleArg})">
                <div class="media-file-icon">${icon}</div>
                <div class="media-file-info">
                    <div class="media-file-name">${escapeHtml(media.fileName)}</div>
                    <div class="media-file-size">${formatBytes(media.fileSize)} · ⬇️ Tap to download E2E file</div>
                </div>
            </div>
        </div>`;
    }

    // Legacy E2E media
    if (!media.data) {
        return `<div class="media-bubble-content" id="${bubbleId}"><em>No data</em></div>`;
    }

    const dataUrl = 'data:' + (media.mimeType || 'application/octet-stream') + ';base64,' + media.data;
    const mime = media.mimeType || '';

    if (mime.startsWith('image/')) {
        return `<div class="media-bubble-content" id="${bubbleId}">
            <img src="${dataUrl}" alt="${escapeHtml(media.fileName)}" style="max-width:100%; border-radius:8px; cursor:pointer;" onclick="window.open('${dataUrl}')">
        </div>`;
    }
    if (mime.startsWith('video/')) {
        return `<div class="media-bubble-content" id="${bubbleId}">
            <video controls src="${dataUrl}" style="max-width:100%; border-radius:8px;"></video>
        </div>`;
    }
    if (mime.startsWith('audio/')) {
        return `<div class="media-bubble-content" id="${bubbleId}">
            <audio controls src="${dataUrl}" style="width:100%;"></audio>
        </div>`;
    }
    const icon = getMediaIcon(mime);
    return `<div class="media-bubble-content" id="${bubbleId}">
        <div class="media-file-card">
            <div class="media-file-icon">${icon}</div>
            <div class="media-file-info">
                <div class="media-file-name">${escapeHtml(media.fileName)}</div>
                <div class="media-file-size">${formatBytes(media.fileSize)} · <a href="${dataUrl}" download="${escapeHtml(media.fileName)}" style="color:var(--accent);">Download</a></div>
            </div>
        </div>
    </div>`;
}

function renderChatMessages() {
    const container = document.getElementById('chatMessages');

    if (!currentRecipient || !chatMessages[currentRecipient] || chatMessages[currentRecipient].length === 0) {
        container.innerHTML = `<div class="chat-empty">
            <div class="chat-empty-icon">🔒</div>
            <div class="chat-empty-text">Messages are end-to-end encrypted.<br>Type a message below to start.</div>
        </div>`;
        return;
    }

    const msgs = chatMessages[currentRecipient];
    container.innerHTML = msgs.map((msg, i) => {
        const time = new Date(msg.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const bubbleId = 'media-' + currentRecipient.replace(/[^a-zA-Z0-9]/g, '') + '-' + i;

        if (msg.type === 'sent') {
            // Sent media
            if (msg.media) {
                return `<div class="chat-bubble sent">
                    <div>📎 ${escapeHtml(msg.media.fileName)}</div>
                    ${renderAutoMedia(msg.media, bubbleId, i, true)}
                    <div class="bubble-meta">${time} · 🔒 E2E</div>
                </div>`;
            }
            // Sent text
            return `<div class="chat-bubble sent">
                <div>${escapeHtml(msg.text)}</div>
                <div class="bubble-meta">${time} · 🔒 E2E</div>
            </div>`;
        } else {
            // Received media
            if (msg.isMedia && msg.media && (msg.media.data || msg.media.mediaType === 'hybrid')) {
                return `<div class="chat-bubble received">
                    <div>📎 ${escapeHtml(msg.media.fileName)}</div>
                    ${renderAutoMedia(msg.media, bubbleId, i, false)}
                    <div class="bubble-meta">${time} · 🔓 Decrypted</div>
                </div>`;
            }
            // Received media without data (decrypt failed or pending)
            if (msg.isMedia || (msg.media && !msg.media.data && msg.media.mediaType !== 'hybrid')) {
                return `<div class="chat-bubble received">
                    <div>📎 ${escapeHtml((msg.media && msg.media.fileName) || 'Media')}</div>
                    ${renderMediaBubble(msg, i, bubbleId)}
                    <div class="bubble-meta">${time} · 🔒 Tap to decrypt</div>
                </div>`;
            }
            // Received text (decrypted)
            if (msg.decryptedText) {
                return `<div class="chat-bubble received">
                    <div>${escapeHtml(msg.decryptedText)}</div>
                    <div class="bubble-meta">${time} · 🔓 Decrypted</div>
                </div>`;
            }
            // Received text (decrypt failed)
            return `<div class="chat-bubble received">
                <div style="color:var(--text3); font-style:italic;">⚠️ Could not decrypt</div>
                <div class="bubble-meta">${time}</div>
            </div>`;
        }
    }).join('');

    // Scroll to bottom
    container.scrollTop = container.scrollHeight;
}

// ──────────────────────────────────────────────────────────
//  LOGS
// ──────────────────────────────────────────────────────────

function addLog(method, url, status, body) {
    const container = document.getElementById('logContainer');
    const time = new Date().toLocaleTimeString();
    const statusClass = status < 400 ? 'ok' : 'err';

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span class="log-time">${time}</span>
        <span class="log-method ${method}">${method}</span>
        <span class="log-url">${escapeHtml(url)}</span>
        <span class="log-status ${statusClass}">${status}</span>
        ${body ? `<div class="log-body">${escapeHtml(typeof body === 'string' ? body : JSON.stringify(body))}</div>` : ''}
    `;
    container.insertBefore(entry, container.firstChild);
}

function clearLogs() {
    document.getElementById('logContainer').innerHTML = '';
    showToast('Logs cleared', 'success');
}

// ──────────────────────────────────────────────────────────
//  TAB NAVIGATION
// ──────────────────────────────────────────────────────────

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
});

// ──────────────────────────────────────────────────────────
//  UTILITY FUNCTIONS
// ──────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(dateStr) {
    if (!dateStr) return '—';
    try {
        return new Date(dateStr).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
    } catch { return dateStr; }
}

function getExtension(filename) {
    return filename.split('.').pop() || '';
}

function maskAadhaar(num) {
    const clean = num.replace(/\s/g, '');
    return 'XXXX' + clean.slice(-4);
}

function setBadge(type, text) {
    const badge = document.getElementById('status-badge');
    badge.className = 'badge badge-' + type;
    badge.textContent = text;
}

function showToast(message, type) {
    // Remove existing toast
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
