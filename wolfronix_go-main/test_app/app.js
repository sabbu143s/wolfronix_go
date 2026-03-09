let wfx = null;
let currentUserId = null;
let activeHomeTab = "vault";
let activeChatId = null;
let chatPollTimer = null;
let vaultPreviewUrl = null;
let vaultPreviewFilename = "decrypted_file";
let profileFileId = null;
const seenPackets = new Set();
const chatMessages = {};
const CHUNKED_MANIFESTS_STORAGE_KEY = "wfx_chunked_manifests_v2";
const CHAT_GROUPS_STORAGE_KEY = "wfx_chat_groups_v1";
const RESUMABLE_THRESHOLD_BYTES = 25 * 1024 * 1024;

const RELAY_URL = window.location.origin;
const PROFILE_FILE_PREFIX = "profile_";
const PROFILE_FILE_ID_CACHE_KEY = "wfx_profile_file_id_v1";
const TEST_CLIENT_CONFIG = {
    baseUrl: "https://49.206.202.13:9443/",
    clientId: "wolfronix_client_1",
    wolfronixKey: "685777a685a8b7fe3aee6c8c54a88698fa28b8dc14faaae495091cdc8520cbaf"
};

window.addEventListener("DOMContentLoaded", initClient);

function initClient() {
    try {
        wfx = new WolfronixSDK.default({
            baseUrl: TEST_CLIENT_CONFIG.baseUrl,
            clientId: TEST_CLIENT_CONFIG.clientId,
            wolfronixKey: TEST_CLIENT_CONFIG.wolfronixKey,
            insecure: true,
            timeout: 30000,
            retries: 3
        });
        wfx.healthCheck().then(ok => {
            setBadge(ok ? "connected" : "degraded", ok ? "Connected" : "Degraded");
        }).catch(() => setBadge("degraded", "Offline"));
        showLogin();
    } catch (err) {
        setBadge("disconnected", "Init Failed");
        showToast("Failed to initialize SDK: " + err.message, "error");
    }
}

function showLogin() {
    showScreen("login");
}

function showRegister() {
    showScreen("register");
}

function showHome() {
    showScreen("home");
}

function showScreen(name) {
    document.getElementById("screen-login").classList.toggle("active", name === "login");
    document.getElementById("screen-register").classList.toggle("active", name === "register");
    document.getElementById("screen-home").classList.toggle("active", name === "home");
}

async function register() {
    if (!wfx) return showToast("SDK not initialized", "error");
    const email = document.getElementById("registerEmail").value.trim();
    const password = document.getElementById("registerPassword").value;
    if (!email || !password) return showToast("Email and password are required", "error");

    try {
        const res = await wfx.register(email, password, { enableRecovery: true });
        const phrase =
            res.recoveryPhrase ||
            res.recovery_phrase ||
            (Array.isArray(res.recoveryWords) ? res.recoveryWords.join(" ") : "") ||
            (Array.isArray(res.recovery_words) ? res.recovery_words.join(" ") : "");
        document.getElementById("registerRecoveryPhrase").value = phrase || "";
        document.getElementById("loginEmail").value = email;
        showToast("Account created. Save recovery phrase and login.", "success");
    } catch (err) {
        showToast("Register failed: " + err.message, "error");
    }
}

async function login() {
    if (!wfx) return showToast("SDK not initialized", "error");
    const email = document.getElementById("loginEmail").value.trim();
    const password = document.getElementById("loginPassword").value;
    if (!email || !password) return showToast("Email and password are required", "error");

    try {
        await wfx.login(email, password);
        currentUserId = email;
        document.getElementById("auth-user-name").textContent = email;
        document.getElementById("auth-user-badge").style.display = "flex";
        showHome();
        switchHomeTab("vault");
        startChatPoll();
        await loadVaultFiles();
        await loadProfile();
        showToast("Logged in successfully", "success");
    } catch (err) {
        showToast("Login failed: " + err.message, "error");
    }
}

function logout() {
    if (wfx) wfx.logout();
    currentUserId = null;
    activeChatId = null;
    profileFileId = null;
    stopChatPoll();
    seenPackets.clear();
    Object.keys(chatMessages).forEach(k => delete chatMessages[k]);
    document.getElementById("auth-user-badge").style.display = "none";
    document.getElementById("chatRecipientInput").value = "";
    const groupIdInput = document.getElementById("groupChatId");
    if (groupIdInput) groupIdInput.value = "";
    const groupMembersInput = document.getElementById("groupChatMembers");
    if (groupMembersInput) groupMembersInput.value = "";
    document.getElementById("chatMessageInput").value = "";
    renderChatContacts();
    renderChatMessages();
    closeVaultPreview();
    setBadge("connected", "Connected");
    showLogin();
}

function switchHomeTab(tab) {
    if (!currentUserId) return;
    activeHomeTab = tab;
    document.getElementById("homeTabVault").classList.toggle("active", tab === "vault");
    document.getElementById("homeTabChat").classList.toggle("active", tab === "chat");
    document.getElementById("homeTabProfile").classList.toggle("active", tab === "profile");
    document.getElementById("home-vault").classList.toggle("active", tab === "vault");
    document.getElementById("home-chat").classList.toggle("active", tab === "chat");
    document.getElementById("home-profile").classList.toggle("active", tab === "profile");
    if (tab === "vault") loadVaultFiles();
    if (tab === "profile") loadProfile();
}

function onVaultFileSelected(input) {
    const file = input.files[0];
    document.getElementById("vaultSelectedFileName").textContent = file ? file.name : "No file selected";
    document.getElementById("vaultUploadBtn").disabled = !file;
}

async function uploadVaultFile() {
    if (!wfx || !wfx.isAuthenticated()) return showToast("Login first", "error");
    const input = document.getElementById("vaultFileInput");
    const file = input.files[0];
    if (!file) return showToast("Select a file first", "error");

    try {
        document.getElementById("vaultUploadBtn").disabled = true;
        const statusEl = document.getElementById("vaultUploadStatus");
        if (file.size >= RESUMABLE_THRESHOLD_BYTES) {
            statusEl.textContent = "Uploading in encrypted chunks...";
            const raw = await wfx.encryptResumable(file, {
                chunkSizeBytes: 10 * 1024 * 1024,
                onProgress: (uploaded, total) => {
                    statusEl.textContent = `Uploading chunks ${uploaded}/${total}...`;
                }
            });
            const result = raw && raw.result ? raw.result : raw;
            if (result && result.complete && Array.isArray(result.chunk_file_ids)) {
                saveChunkedManifest({
                    upload_id: result.upload_id || (Date.now() + "-" + Math.random().toString(36).slice(2, 8)),
                    filename: result.filename || file.name,
                    total_chunks: result.total_chunks || result.chunk_file_ids.length,
                    chunk_size_bytes: result.chunk_size_bytes || 10 * 1024 * 1024,
                    chunk_file_ids: result.chunk_file_ids
                });
            }
            statusEl.textContent = "Large file upload complete.";
        } else {
            statusEl.textContent = "Encrypting and uploading...";
            await wfx.encrypt(file);
            statusEl.textContent = "Upload complete.";
        }
        input.value = "";
        onVaultFileSelected(input);
        await loadVaultFiles();
        showToast("File uploaded and encrypted", "success");
    } catch (err) {
        showToast("Upload failed: " + err.message, "error");
    } finally {
        const statusEl = document.getElementById("vaultUploadStatus");
        setTimeout(() => {
            if (statusEl) statusEl.textContent = "";
        }, 2500);
        document.getElementById("vaultUploadBtn").disabled = false;
    }
}

function isChunkPartFile(name) {
    return /\.part-\d+-of-\d+$/i.test(name || "");
}

async function loadVaultFiles() {
    if (!wfx || !wfx.isAuthenticated()) return;
    const container = document.getElementById("vaultFileList");
    try {
        const { files } = await wfx.listFiles();
        const chunkedManifests = listChunkedManifests();
        const chunkPartIds = new Set(chunkedManifests.flatMap(m => Array.isArray(m.chunk_file_ids) ? m.chunk_file_ids : []));
        const visibleFiles = files.filter(f =>
            !String(f.original_name || "").startsWith(PROFILE_FILE_PREFIX) &&
            !isChunkPartFile(f.original_name || "") &&
            !chunkPartIds.has(f.file_id)
        );

        const chunkedHtml = chunkedManifests.map(m => `
            <div class="vault-item">
                <div class="vault-item-icon file">L</div>
                <div class="vault-item-info">
                    <div class="item-name">${escapeHtml(m.filename || "large_file.bin")}</div>
                    <div class="item-meta">Large file · ${escapeHtml(String(m.total_chunks || (m.chunk_file_ids || []).length))} chunks</div>
                </div>
                <div class="vault-item-actions">
                    <button class="btn-view" onclick="decryptChunkedVaultFile('${escapeJs(m.upload_id)}')">Decrypt</button>
                    <button class="btn-delete" onclick="deleteChunkedVaultFile('${escapeJs(m.upload_id)}')">Delete</button>
                </div>
            </div>
        `).join("");

        if (!visibleFiles.length && !chunkedHtml) {
            container.innerHTML = '<p class="placeholder">No files yet.</p>';
            return;
        }
        const regularHtml = visibleFiles.map(file => `
            <div class="vault-item">
                <div class="vault-item-icon file">F</div>
                <div class="vault-item-info">
                    <div class="item-name">${escapeHtml(file.original_name)}</div>
                    <div class="item-meta">ID: ${escapeHtml(file.file_id)} · ${formatBytes(file.encrypted_size)}</div>
                </div>
                <div class="vault-item-actions">
                    <button class="btn-view" onclick="decryptVaultFile('${escapeJs(file.file_id)}', '${escapeJs(file.original_name)}')">Decrypt</button>
                    <button class="btn-delete" onclick="deleteVaultFile('${escapeJs(file.file_id)}')">Delete</button>
                </div>
            </div>
        `).join("");
        container.innerHTML = chunkedHtml + regularHtml;
    } catch (err) {
        container.innerHTML = '<p class="placeholder">Failed to load files.</p>';
        showToast("List files failed: " + err.message, "error");
    }
}

async function decryptChunkedVaultFile(uploadId) {
    if (!wfx || !wfx.isAuthenticated()) return showToast("Login first", "error");
    const manifest = getChunkedManifestByUploadId(uploadId);
    if (!manifest) return showToast("Chunk manifest not found", "error");
    try {
        let blob;
        try {
            blob = await wfx.decryptChunkedManifest(manifest);
        } catch (sdkErr) {
            // Fallback: decrypt each chunk manually and stitch to handle SDK/runtime mismatch cases.
            const parts = [];
            let totalBytes = 0;
            for (let i = 0; i < (manifest.chunk_file_ids || []).length; i++) {
                const chunkId = manifest.chunk_file_ids[i];
                try {
                    const buf = await wfx.decryptToBuffer(chunkId);
                    const part = new Uint8Array(buf);
                    parts.push(part);
                    totalBytes += part.byteLength;
                } catch (chunkErr) {
                    throw new Error(`Chunk ${i + 1} decrypt failed (file_id=${chunkId}): ${chunkErr.message}`);
                }
            }
            const merged = new Uint8Array(totalBytes);
            let offset = 0;
            for (const p of parts) {
                merged.set(p, offset);
                offset += p.byteLength;
            }
            blob = new Blob([merged.buffer], { type: detectMimeFromFilename(manifest.filename) });
        }
        showVaultPreview(blob, manifest.filename || "large_file.bin");
        showToast("Large file decrypted", "success");
    } catch (err) {
        showToast("Chunked decrypt failed: " + err.message, "error");
    }
}

async function deleteChunkedVaultFile(uploadId) {
    if (!wfx || !wfx.isAuthenticated()) return showToast("Login first", "error");
    const manifest = getChunkedManifestByUploadId(uploadId);
    if (!manifest) return showToast("Chunk manifest not found", "error");
    try {
        for (const fid of manifest.chunk_file_ids || []) {
            if (!fid) continue;
            await wfx.deleteFile(fid).catch(() => null);
        }
        removeChunkedManifestByUploadId(uploadId);
        await loadVaultFiles();
        showToast("Large file deleted", "success");
    } catch (err) {
        showToast("Delete failed: " + err.message, "error");
    }
}

async function decryptVaultFile(fileId, fileName) {
    if (!wfx || !wfx.isAuthenticated()) return showToast("Login first", "error");
    try {
        const blob = await wfx.decrypt(fileId);
        showVaultPreview(blob, fileName || "decrypted_file");
    } catch (err) {
        showToast("Decrypt failed: " + err.message, "error");
    }
}

async function deleteVaultFile(fileId) {
    if (!wfx || !wfx.isAuthenticated()) return showToast("Login first", "error");
    try {
        await wfx.deleteFile(fileId);
        await loadVaultFiles();
        showToast("File deleted", "success");
    } catch (err) {
        showToast("Delete failed: " + err.message, "error");
    }
}

function showVaultPreview(blob, filename) {
    closeVaultPreview();
    vaultPreviewFilename = filename || "decrypted_file";
    vaultPreviewUrl = URL.createObjectURL(blob);
    const content = document.getElementById("vaultPreviewContent");
    const title = document.getElementById("vaultPreviewTitle");
    const card = document.getElementById("vaultPreviewCard");
    const detectedMime = detectMimeFromFilename(vaultPreviewFilename);
    const mime = (!blob.type || blob.type === "application/octet-stream")
        ? detectedMime
        : blob.type;

    title.textContent = vaultPreviewFilename;
    if (mime.startsWith("image/")) {
        content.innerHTML = `<img src="${vaultPreviewUrl}" class="preview-image" alt="${escapeHtml(vaultPreviewFilename)}">`;
    } else if (mime.startsWith("video/")) {
        content.innerHTML = `<video class="preview-video" controls src="${vaultPreviewUrl}"></video>`;
    } else if (mime.startsWith("audio/")) {
        content.innerHTML = `<audio class="preview-audio" controls src="${vaultPreviewUrl}"></audio>`;
    } else if (mime === "application/pdf") {
        content.innerHTML = `<iframe class="preview-pdf" src="${vaultPreviewUrl}"></iframe>`;
    } else {
        content.innerHTML = `<div class="preview-binary"><div class="preview-binary-icon">File</div><div>${escapeHtml(vaultPreviewFilename)}</div></div>`;
    }
    card.style.display = "block";
}

function closeVaultPreview() {
    if (vaultPreviewUrl) {
        URL.revokeObjectURL(vaultPreviewUrl);
        vaultPreviewUrl = null;
    }
    const card = document.getElementById("vaultPreviewCard");
    const content = document.getElementById("vaultPreviewContent");
    if (content) content.innerHTML = "";
    if (card) card.style.display = "none";
}

function downloadVaultPreview() {
    if (!vaultPreviewUrl) return;
    const a = document.createElement("a");
    a.href = vaultPreviewUrl;
    a.download = vaultPreviewFilename || "decrypted_file";
    a.click();
}

function openChat() {
    if (!wfx || !wfx.isAuthenticated()) return showToast("Login first", "error");
    const recipient = document.getElementById("chatRecipientInput").value.trim();
    if (!recipient) return showToast("Enter recipient ID", "error");
    if (!chatMessages[recipient]) chatMessages[recipient] = [];
    activeChatId = recipient;
    document.getElementById("chatHeaderName").textContent = recipient;
    document.getElementById("chatAvatar").textContent = recipient.charAt(0).toUpperCase();
    renderChatContacts();
    renderChatMessages();
}

function groupConversationId(groupId) {
    return "group:" + String(groupId || "").trim();
}

function isGroupConversation(conversationId) {
    return String(conversationId || "").startsWith("group:");
}

function parseGroupMembers(raw) {
    return Array.from(new Set(String(raw || "")
        .split(/[\n,]/)
        .map(x => x.trim())
        .filter(Boolean)));
}

function loadGroups() {
    try {
        const raw = localStorage.getItem(CHAT_GROUPS_STORAGE_KEY);
        const parsed = raw ? JSON.parse(raw) : {};
        return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
        return {};
    }
}

function saveGroups(groups) {
    localStorage.setItem(CHAT_GROUPS_STORAGE_KEY, JSON.stringify(groups || {}));
}

function upsertGroup(groupId, members) {
    const id = String(groupId || "").trim();
    if (!id) return null;
    const groups = loadGroups();
    const existing = groups[id] || { group_id: id, members: [] };
    const merged = Array.from(new Set([...(existing.members || []), ...(members || [])].filter(Boolean)));
    groups[id] = { group_id: id, members: merged, updated_at: Date.now() };
    saveGroups(groups);
    return groups[id];
}

function getGroup(groupId) {
    const groups = loadGroups();
    return groups[String(groupId || "").trim()] || null;
}

function openGroupChat() {
    if (!wfx || !wfx.isAuthenticated()) return showToast("Login first", "error");
    const groupId = (document.getElementById("groupChatId").value || "").trim();
    if (!groupId) return showToast("Enter group ID", "error");
    const members = parseGroupMembers(document.getElementById("groupChatMembers").value || "");
    if (currentUserId && !members.includes(currentUserId)) members.push(currentUserId);
    if (members.length < 2) return showToast("Add at least two members including you", "error");
    upsertGroup(groupId, members);
    switchChat(groupConversationId(groupId));
}

function switchChat(recipient) {
    if (!chatMessages[recipient]) chatMessages[recipient] = [];
    activeChatId = recipient;
    if (isGroupConversation(recipient)) {
        const groupId = recipient.slice("group:".length);
        const group = getGroup(groupId);
        document.getElementById("chatRecipientInput").value = "";
        const groupIdInput = document.getElementById("groupChatId");
        if (groupIdInput) groupIdInput.value = groupId;
        const membersInput = document.getElementById("groupChatMembers");
        if (membersInput && group && Array.isArray(group.members)) membersInput.value = group.members.join(", ");
        document.getElementById("chatHeaderName").textContent = "#" + groupId;
        document.getElementById("chatAvatar").textContent = "#";
    } else {
        document.getElementById("chatRecipientInput").value = recipient;
        document.getElementById("chatHeaderName").textContent = recipient;
        document.getElementById("chatAvatar").textContent = recipient.charAt(0).toUpperCase();
    }
    renderChatContacts();
    renderChatMessages();
}

async function sendChatMessage() {
    if (!wfx || !wfx.isAuthenticated()) return showToast("Login first", "error");
    const textInput = document.getElementById("chatMessageInput");
    const text = textInput.value.trim();
    if (!text) return;

    if (!activeChatId) {
        const typedRecipient = document.getElementById("chatRecipientInput").value.trim();
        if (!typedRecipient) return showToast("Enter recipient ID", "error");
        switchChat(typedRecipient);
    }

    try {
        if (isGroupConversation(activeChatId)) {
            const groupId = activeChatId.slice("group:".length);
            const group = getGroup(groupId);
            if (!group || !Array.isArray(group.members) || group.members.length < 2) {
                return showToast("Group members not configured", "error");
            }
            const packet = await wfx.encryptGroupMessage(text, groupId, group.members);
            const packetObj = JSON.parse(packet);
            const recipients = Object.keys(packetObj.recipient_keys || {}).filter(id => id && id !== currentUserId);
            await Promise.all(recipients.map(to =>
                fetch(RELAY_URL + "/api/chat/send", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ to, from: currentUserId, packet })
                }).catch(() => null)
            ));
        } else {
            const packet = await wfx.encryptMessage(text, activeChatId);
            await fetch(RELAY_URL + "/api/chat/send", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ to: activeChatId, from: currentUserId, packet })
            }).catch(() => null);
        }

        chatMessages[activeChatId].push({
            type: "sent",
            text,
            time: new Date().toISOString()
        });
        textInput.value = "";
        renderChatMessages();
        renderChatContacts();
    } catch (err) {
        showToast("Send failed: " + err.message, "error");
    }
}

function renderChatContacts() {
    const container = document.getElementById("chatContacts");
    const ids = Object.keys(chatMessages);
    if (!ids.length) {
        container.innerHTML = '<p class="placeholder" style="padding:12px; font-size:12px;">No conversations yet</p>';
        return;
    }

    container.innerHTML = ids.map(id => {
        const messages = chatMessages[id] || [];
        const last = messages[messages.length - 1];
        const lastText = last ? (last.text || "Encrypted") : "No messages";
        const active = id === activeChatId ? "active" : "";
        const isGroup = isGroupConversation(id);
        const displayName = isGroup ? ("#" + id.slice("group:".length)) : id;
        const avatar = isGroup ? "#" : id.charAt(0).toUpperCase();
        return `
            <div class="chat-contact ${active}" onclick="switchChat('${escapeJs(id)}')">
                <div class="chat-contact-avatar">${escapeHtml(avatar)}</div>
                <div>
                    <div class="chat-contact-name">${escapeHtml(displayName)}</div>
                    <div class="chat-contact-last">${escapeHtml(lastText.slice(0, 35))}</div>
                </div>
            </div>
        `;
    }).join("");
}

function renderChatMessages() {
    const container = document.getElementById("chatMessages");
    if (!activeChatId || !chatMessages[activeChatId] || !chatMessages[activeChatId].length) {
        container.innerHTML = `
            <div class="chat-empty">
                <div class="chat-empty-icon">Chat</div>
                <div class="chat-empty-text">No messages yet.</div>
            </div>
        `;
        return;
    }

    container.innerHTML = chatMessages[activeChatId].map(msg => {
        const time = new Date(msg.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        if (msg.type === "sent") {
            return `<div class="chat-bubble sent"><div>${escapeHtml(msg.text)}</div><div class="bubble-meta">${time}</div></div>`;
        }
        const senderLine = isGroupConversation(activeChatId) && msg.sender ? `<div class="bubble-meta">${escapeHtml(msg.sender)}</div>` : "";
        return `<div class="chat-bubble received">${senderLine}<div>${escapeHtml(msg.text || "Could not decrypt")}</div><div class="bubble-meta">${time}</div></div>`;
    }).join("");
    container.scrollTop = container.scrollHeight;
}

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
        const res = await fetch(RELAY_URL + "/api/chat/messages?userId=" + encodeURIComponent(currentUserId));
        const json = await res.json();
        const messages = Array.isArray(json.messages) ? json.messages : [];

        for (const msg of messages) {
            const packetKey = String(msg.packet || "") + "|" + String(msg.timestamp || "");
            if (seenPackets.has(packetKey)) continue;
            seenPackets.add(packetKey);
            if (seenPackets.size > 5000) {
                const first = seenPackets.values().next().value;
                seenPackets.delete(first);
            }

            const sender = msg.from || "unknown";
            let threadId = sender;
            let isGroupPacket = false;
            let packetObj = null;
            try {
                packetObj = JSON.parse(msg.packet || "{}");
                if (packetObj && packetObj.type === "group_sender_key" && packetObj.group_id) {
                    isGroupPacket = true;
                    threadId = groupConversationId(packetObj.group_id);
                    const members = Object.keys(packetObj.recipient_keys || {});
                    upsertGroup(packetObj.group_id, members);
                }
            } catch {
                // packet is not json or not a group packet
            }
            if (!chatMessages[threadId]) chatMessages[threadId] = [];
            let text = null;
            try {
                text = isGroupPacket ? await wfx.decryptGroupMessage(msg.packet) : await wfx.decryptMessage(msg.packet);
            } catch {
                text = null;
            }
            chatMessages[threadId].push({
                type: "received",
                text,
                sender,
                time: new Date(msg.timestamp || Date.now()).toISOString()
            });
            if (threadId !== activeChatId) showToast("New message", "success");
        }
        renderChatContacts();
        renderChatMessages();
    } catch {
        // Keep silent for relay downtime.
    }
}

function profileFileNameForUser() {
    return PROFILE_FILE_PREFIX + String(currentUserId || "").replace(/[^a-zA-Z0-9@._-]/g, "_") + ".json";
}

function safeParseJsonText(text) {
    const raw = String(text || "");
    const cleaned = raw
        .replace(/^\uFEFF/, "")
        .replace(/\u0000/g, "")
        .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F]/g, "")
        .trim();

    try {
        return JSON.parse(cleaned);
    } catch {
        const start = cleaned.indexOf("{");
        const end = cleaned.lastIndexOf("}");
        if (start >= 0 && end > start) {
            const slice = cleaned.slice(start, end + 1);
            return JSON.parse(slice);
        }
        throw new Error("Profile JSON parse failed");
    }
}

async function loadProfile() {
    if (!wfx || !wfx.isAuthenticated() || !currentUserId) return;
    profileFileId = null;
    try {
        const { files } = await wfx.listFiles();
        const targetName = profileFileNameForUser();
        const cachedId = localStorage.getItem(PROFILE_FILE_ID_CACHE_KEY) || "";
        const matches = files
            .filter(f => f.original_name === targetName)
            .sort((a, b) => {
                const ta = Date.parse(a.created_at || "") || 0;
                const tb = Date.parse(b.created_at || "") || 0;
                return tb - ta;
            });

        if (cachedId) {
            const idx = matches.findIndex(f => f.file_id === cachedId);
            if (idx > 0) {
                const hit = matches.splice(idx, 1)[0];
                matches.unshift(hit);
            }
        }

        if (!matches.length) {
            clearProfileForm();
            document.getElementById("profileMeta").textContent = "No profile saved yet.";
            return;
        }

        let loaded = false;
        for (const match of matches) {
            try {
                const buffer = await wfx.decryptToBuffer(match.file_id);
                const text = new TextDecoder().decode(buffer);
                const profile = safeParseJsonText(text);
                profileFileId = match.file_id;
                localStorage.setItem(PROFILE_FILE_ID_CACHE_KEY, profileFileId);

                document.getElementById("profileFullName").value = profile.full_name || "";
                document.getElementById("profilePhone").value = profile.phone || "";
                document.getElementById("profileDob").value = profile.dob || "";
                document.getElementById("profileCity").value = profile.city || "";
                document.getElementById("profileAddress").value = profile.address || "";
                document.getElementById("profileMeta").textContent = "Profile loaded.";
                loaded = true;
                break;
            } catch {
                // try older profile file if current one is corrupted/non-JSON
            }
        }

        if (!loaded) {
            clearProfileForm();
            profileFileId = matches[0].file_id;
            document.getElementById("profileMeta").textContent = "Profile data is corrupted. Save again to overwrite.";
            showToast("Profile file is not valid JSON. Please save profile again.", "error");
        }
    } catch (err) {
        document.getElementById("profileMeta").textContent = "Failed to load profile.";
        showToast("Load profile failed: " + err.message, "error");
    }
}

async function saveProfile() {
    if (!wfx || !wfx.isAuthenticated() || !currentUserId) return showToast("Login first", "error");
    const payload = {
        user_id: currentUserId,
        full_name: document.getElementById("profileFullName").value.trim(),
        phone: document.getElementById("profilePhone").value.trim(),
        dob: document.getElementById("profileDob").value,
        city: document.getElementById("profileCity").value.trim(),
        address: document.getElementById("profileAddress").value.trim(),
        updated_at: new Date().toISOString()
    };
    try {
        const targetName = profileFileNameForUser();
        const { files } = await wfx.listFiles();
        const oldProfiles = files.filter(f => f.original_name === targetName);
        for (const old of oldProfiles) {
            await wfx.deleteFile(old.file_id).catch(() => null);
        }
        profileFileId = null;
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        const res = await wfx.encrypt(blob, targetName);
        profileFileId = res.file_id;
        localStorage.setItem(PROFILE_FILE_ID_CACHE_KEY, profileFileId);
        document.getElementById("profileMeta").textContent = "Profile saved.";
        showToast("Profile saved", "success");
    } catch (err) {
        showToast("Save profile failed: " + err.message, "error");
    }
}

async function repairProfile() {
    if (!wfx || !wfx.isAuthenticated() || !currentUserId) return showToast("Login first", "error");
    try {
        const targetName = profileFileNameForUser();
        const { files } = await wfx.listFiles();
        const profileFiles = files.filter(f => f.original_name === targetName);
        for (const f of profileFiles) {
            await wfx.deleteFile(f.file_id).catch(() => null);
        }
        profileFileId = null;
        localStorage.removeItem(PROFILE_FILE_ID_CACHE_KEY);
        clearProfileForm();
        document.getElementById("profileMeta").textContent = "Old profile files removed. Save profile now.";
        showToast("Profile repaired. Please save profile again.", "success");
    } catch (err) {
        showToast("Repair failed: " + err.message, "error");
    }
}

function listChunkedManifests() {
    try {
        const raw = localStorage.getItem(CHUNKED_MANIFESTS_STORAGE_KEY);
        const parsed = raw ? JSON.parse(raw) : [];
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function saveChunkedManifest(manifest) {
    if (!manifest || !manifest.upload_id || !Array.isArray(manifest.chunk_file_ids)) return;
    const all = listChunkedManifests().filter(m => m.upload_id !== manifest.upload_id);
    all.unshift({
        upload_id: String(manifest.upload_id),
        filename: manifest.filename || "large_file.bin",
        total_chunks: manifest.total_chunks || manifest.chunk_file_ids.length,
        chunk_size_bytes: manifest.chunk_size_bytes || 10 * 1024 * 1024,
        chunk_file_ids: manifest.chunk_file_ids.slice()
    });
    localStorage.setItem(CHUNKED_MANIFESTS_STORAGE_KEY, JSON.stringify(all.slice(0, 300)));
}

function getChunkedManifestByUploadId(uploadId) {
    return listChunkedManifests().find(m => m.upload_id === uploadId) || null;
}

function removeChunkedManifestByUploadId(uploadId) {
    const next = listChunkedManifests().filter(m => m.upload_id !== uploadId);
    localStorage.setItem(CHUNKED_MANIFESTS_STORAGE_KEY, JSON.stringify(next));
}

function clearProfileForm() {
    document.getElementById("profileFullName").value = "";
    document.getElementById("profilePhone").value = "";
    document.getElementById("profileDob").value = "";
    document.getElementById("profileCity").value = "";
    document.getElementById("profileAddress").value = "";
}

function setBadge(type, text) {
    const badge = document.getElementById("status-badge");
    badge.className = "badge badge-" + type;
    badge.textContent = text;
}

function showToast(message, type) {
    const old = document.querySelector(".toast");
    if (old) old.remove();
    const el = document.createElement("div");
    el.className = "toast " + (type || "success");
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => {
        el.style.opacity = "0";
        setTimeout(() => el.remove(), 250);
    }, 3000);
}

function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
}

function detectMimeFromFilename(name) {
    const n = String(name || "").toLowerCase();
    if (n.endsWith(".png")) return "image/png";
    if (n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
    if (n.endsWith(".gif")) return "image/gif";
    if (n.endsWith(".webp")) return "image/webp";
    if (n.endsWith(".mp4")) return "video/mp4";
    if (n.endsWith(".mkv")) return "video/x-matroska";
    if (n.endsWith(".webm")) return "video/webm";
    if (n.endsWith(".mov")) return "video/quicktime";
    if (n.endsWith(".avi")) return "video/x-msvideo";
    if (n.endsWith(".mp3")) return "audio/mpeg";
    if (n.endsWith(".wav")) return "audio/wav";
    if (n.endsWith(".ogg")) return "audio/ogg";
    if (n.endsWith(".pdf")) return "application/pdf";
    return "application/octet-stream";
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = String(str ?? "");
    return div.innerHTML;
}

function escapeJs(str) {
    return String(str ?? "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}
