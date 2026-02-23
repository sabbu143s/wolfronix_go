# Wolfronix — Complete System Workflow

> **SDK v2.4.1** · **Engine v2** · Last updated: February 2026

## The Big Picture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           YOUR APP (Browser / Node.js)                          │
│                                                                                 │
│   ┌──────────────────────┐    ┌──────────────────────────────────────────────┐  │
│   │  @wolfronix/sdk      │    │  Your Frontend (React, Vue, etc.)           │  │
│   │  v2.4.1              │    │  Uses SDK methods directly                  │  │
│   │                      │    │                                              │  │
│   │  • register()        │    │  wfx.register('email', 'pass')              │  │
│   │  • login()           │    │  wfx.encrypt(file)                          │  │
│   │  • encrypt()         │    │  wfx.decrypt(fileId)                        │  │
│   │  • decrypt()         │    │  wfx.listFiles()                            │  │
│   │  • deleteFile()      │    │  wfx.serverEncrypt('Hello')                 │  │
│   │  • serverEncrypt()   │    │  wfx.serverDecrypt(params)                  │  │
│   │  • serverDecrypt()   │    │  wfx.serverEncryptBatch(messages)           │  │
│   │  • createStream()    │    │  wfx.createStream('encrypt')                │  │
│   │  • encryptMessage()  │    │  wfx.encryptMessage(text, recipientId)      │  │
│   │  • decryptMessage()  │    │                                              │  │
│   └──────────┬───────────┘    └──────────────────────────────────────────────┘  │
│              │                                                                  │
│   All crypto (RSA keygen, PBKDF2, RSA-OAEP decrypt) happens HERE               │
│   Private key NEVER leaves this box                                             │
└──────────────┬──────────────────────────────────────────────────────────────────┘
               │ HTTPS (TLS) + WebSocket (WSS)
               ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                   WOLFRONIX GO ENGINE  (port 5001, HTTPS + WSS)                 │
│                                                                                  │
│   Middleware: corsMiddleware → apiKeyAuthMiddleware → getAuthenticatedClientID   │
│                                                                                  │
│   ┌────────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│   │ Layer 1    │  │ Layer 2    │  │ Layer 3      │  │ Layer 4              │   │
│   │ Fake Data  │  │ RBAC       │  │ AES-256-GCM  │  │ Dual-Key Split       │   │
│   │ (dev mode) │  │ Masking    │  │ Encrypt/Dec  │  │ RSA-OAEP             │   │
│   └────────────┘  └────────────┘  └──────────────┘  └──────────────────────┘   │
│                                                                                  │
│   ┌────────────────────────────────────────────────────────────────────────┐     │
│   │  Message Encryption + Real-Time Streaming (WebSocket)                 │     │
│   │  • /api/v1/messages/encrypt      — single message AES-GCM            │     │
│   │  • /api/v1/messages/decrypt      — single message decrypt             │     │
│   │  • /api/v1/messages/batch/encrypt — up to 100 messages in one trip   │     │
│   │  • /api/v1/stream (WSS)          — real-time chunk encrypt/decrypt   │     │
│   └────────────────────────────────────────────────────────────────────────┘     │
│                                                                                  │
│   Stores in Wolfronix PostgreSQL:                                                │
│     • client_registry (enterprise client configs)                                │
│     • user_keys (wrapped public+private keys)                                    │
│     • metrics (encryption/decryption stats)                                      │
│     • ephemeral message keys (in-memory, 24h TTL)                                │
│                                                                                  │
│   Does NOT store: actual encrypted files or raw private keys                     │
└──────────────┬───────────────────────────────────────────────────────────────────┘
               │ HTTP (clientDBConn)
               ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      CLIENT'S OWN DATABASE / API                                 │
│                                                                                  │
│   This is YOUR server — Wolfronix pushes encrypted data here                    │
│     • Encrypted file blobs                                                       │
│     • File metadata (key_part_a, key_part_b, IV, filename)                      │
│     • Fake data (dev mode)                                                       │
│                                                                                  │
│   Wolfronix NEVER stores your encrypted files on its own servers                 │
└──────────────────────────────────────────────────────────────────────────────────┘

               ┌───────────────────────────────────────────────────────────────┐
               │              WOLFRONIX SaaS PLATFORM (optional)               │
               │              (Node.js + Prisma + PostgreSQL)                  │
               │                                                               │
               │   What it does:                                               │
               │     • User registration (email/password/Google OAuth)         │
               │     • Subscription management (Starter/Pro/Enterprise)        │
               │     • API key provisioning (wfx_xxx keys)                     │
               │     • Usage dashboard & billing                               │
               │     • Calls Wolfronix Engine's /enterprise/register           │
               │       to create client entry for each SaaS user               │
               │     • Revocation → calls DELETE /enterprise/clients/{id}      │
               │                                                               │
               │   Routes: /api/auth/*, /api/subscription/*, /api/wolfronix/* │
               └───────────────────────────────────────────────────────────────┘
```

---

## The 4 Security Layers

| Layer | Name | When it runs | What it does |
|-------|------|-------------|-------------|
| **Layer 1** | Fake Data Masking | During **encryption** (dev mode only) | Generates realistic-looking decoy data (fake names, emails, phone numbers) and stores it alongside the encrypted file. If someone breaches the dev DB, they find fake data, not real data. Only triggers when `X-Environment: dev` header is sent. |
| **Layer 2** | RBAC Dynamic Masking | During **decryption** (on text files) | After decrypting, the engine scans text content for sensitive patterns (PAN, Aadhaar, credit card, email, phone, SSN) and masks them based on the requester's role. `owner`/`admin` = full access. `analyst` = partial masking. `guest` = full masking (`**********`). Binary files (PDF, images) pass through unmasked. |
| **Layer 3** | AES-256-GCM Encryption | During **encryption** and **decryption** | Random 32-byte key → AES-256-GCM authenticated encryption. Nonce is prepended to ciphertext. GCM provides both confidentiality AND integrity (tamper detection). |
| **Layer 4** | Dual-Key RSA Split | During **encryption** and **decryption** | The 32-byte AES key is split in half. First 16 bytes encrypted with **User's RSA Public Key**. Last 16 bytes encrypted with **Server's RSA Public Key**. Neither party alone can decrypt. Both halves must be reunited. |

---

## Workflow 1: Registration

```
 BROWSER (SDK)                              WOLFRONIX ENGINE
 ─────────────                              ────────────────
     │
     │  1. generateKeyPair()
     │     → RSA-OAEP 2048-bit keypair
     │     → publicKey + privateKey (CryptoKey objects)
     │
     │  2. exportKeyToPEM(publicKey, 'public')
     │     → PEM string (-----BEGIN PUBLIC KEY-----)
     │
     │  3. wrapPrivateKey(privateKey, password)
     │     → Salt: random 16 bytes
     │     → PBKDF2(password, salt, 100000 iterations, SHA-256) → wrapping key
     │     → AES-GCM encrypt(PKCS8-exported private key, wrapping key)
     │     → result: { encryptedKey: base64(IV + ciphertext), salt: hex }
     │
     │  4. POST /api/v1/keys/register
     │     {
     │       client_id: "your-client-id",
     │       user_id: "user@email.com",
     │       public_key_pem: "-----BEGIN PUBLIC KEY-----...",
     │       encrypted_private_key: "base64...",
     │       salt: "hex..."
     │     }
     │────────────────────────────────────────►│
     │                                         │  5. Validate all fields present
     │                                         │
     │                                         │  6. keyWrapStore.StoreWrappedKey()
     │                                         │     → INSERT INTO user_keys
     │                                         │       (Wolfronix's own PostgreSQL)
     │                                         │
     │                                         │  ⚠️ Server NEVER sees raw private key
     │                                         │     Only the encrypted blob
     │◄────────────────────────────────────────│
     │  Response: { status: "success" }
     │
     │  7. SDK stores in memory:
     │     this.publicKey = CryptoKey
     │     this.privateKey = CryptoKey  ← raw, usable
     │     this.publicKeyPEM = PEM string
     │     this.token = 'zk-session'
```

**SDK code that does this:**
```typescript
const wfx = new Wolfronix({
  baseUrl: 'https://your-wolfronix:5002',
  clientId: 'your-client-id',
  wolfronixKey: 'wfx_your-api-key'
});

await wfx.register('user@email.com', 'myPassword123');
// Keys generated client-side, wrapped with password, stored server-side
```

---

## Workflow 2: Login

```
 BROWSER (SDK)                              WOLFRONIX ENGINE
 ─────────────                              ────────────────
     │
     │  1. POST /api/v1/keys/login
     │     { client_id: "...", user_id: "user@email.com" }
     │────────────────────────────────────────►│
     │                                         │  2. keyWrapStore.GetWrappedKey()
     │                                         │     → SELECT FROM user_keys
     │                                         │
     │◄────────────────────────────────────────│
     │  Response: {
     │    public_key_pem: "-----BEGIN PUBLIC KEY-----...",
     │    encrypted_private_key: "base64...",
     │    salt: "hex..."
     │  }
     │
     │  3. unwrapPrivateKey(encrypted_private_key, password, salt)
     │     → PBKDF2(password, salt, 100K, SHA-256) → wrapping key
     │     → AES-GCM decrypt(encrypted blob) → PKCS8 bytes
     │     → importKey(PKCS8) → CryptoKey
     │     ★ If password is WRONG → AES-GCM auth tag fails → "Invalid password"
     │
     │  4. importKeyFromPEM(public_key_pem, 'public') → CryptoKey
     │
     │  5. SDK stores in memory:
     │     this.privateKey = CryptoKey  ← ready to use
     │     this.publicKey = CryptoKey
     │     this.publicKeyPEM = PEM string
     │     this.token = 'zk-session'
```

**SDK code:**
```typescript
await wfx.login('user@email.com', 'myPassword123');
// Fetches encrypted private key → decrypts locally with password
// Wrong password = instant error (AES-GCM tag mismatch)
```

**Password acts as your proof of identity.** The server can't decrypt your private key — only you can.

---

## Workflow 3: Encrypt (Write) — Layers 1, 3, 4

```
 BROWSER (SDK)                              WOLFRONIX ENGINE                    CLIENT'S DB
 ─────────────                              ────────────────                    ───────────
     │
     │  1. FormData:
     │     file = <raw file bytes>
     │     client_public_key = this.publicKeyPEM
     │     user_id = this.userId
     │
     │  POST /api/v1/encrypt
     │────────────────────────────────────────►│
     │                                         │
     │                                    ┌────┴──────────────────────────────────┐
     │                                    │  LAYER 3: AES-256-GCM ENCRYPTION     │
     │                                    │                                       │
     │                                    │  key = crypto/rand (32 bytes)         │
     │                                    │  nonce = crypto/rand (12 bytes)       │
     │                                    │  encrypted = AES-GCM.Seal(           │
     │                                    │    nonce, nonce, plaintext, nil       │
     │                                    │  )                                    │
     │                                    │  → nonce prepended to ciphertext     │
     │                                    └────┬──────────────────────────────────┘
     │                                         │
     │                                    ┌────┴──────────────────────────────────┐
     │                                    │  LAYER 4: DUAL-KEY SPLIT             │
     │                                    │                                       │
     │                                    │  key_part_a = RSA-OAEP encrypt(      │
     │                                    │    key[0:16],  ← first 16 bytes      │
     │                                    │    USER's public key                  │
     │                                    │  )                                    │
     │                                    │                                       │
     │                                    │  key_part_b = RSA-OAEP encrypt(      │
     │                                    │    key[16:32], ← last 16 bytes       │
     │                                    │    SERVER's public key                │
     │                                    │  )                                    │
     │                                    └────┬──────────────────────────────────┘
     │                                         │
     │                                         │  Store via clientDBConn:
     │                                         │  ─────────────────────────────────►│
     │                                         │  • encrypted file blob             │
     │                                         │  • key_part_a (RSA encrypted)      │
     │                                         │  • key_part_b (RSA encrypted)      │
     │                                         │  • IV/nonce (base64)               │
     │                                         │  • filename, size, timestamps      │
     │                                         │  ◄─────────────────────────────────│
     │                                         │  Returns: file_id                  │
     │                                         │
     │                                    ┌────┴──────────────────────────────────┐
     │                                    │  LAYER 1: FAKE DATA (dev mode only)  │
     │                                    │  if X-Environment: dev               │
     │                                    │    → generate fake decoy data        │
     │                                    │    → store in client's dev DB        │
     │                                    └────┬──────────────────────────────────┘
     │                                         │
     │◄────────────────────────────────────────│
     │  Response: {
     │    status: "success",
     │    file_id: 42,
     │    file_size: 1048576,
     │    enc_time_ms: 23,
     │    timing: {
     │      upload_ms: 1200,     ← network transfer time
     │      read_ms: 5,          ← reading file into memory
     │      encrypt_ms: 18,      ← AES-256-GCM encryption
     │      store_ms: 45         ← writing to client DB
     │    }
     │  }
```

**SDK code:**
```typescript
// Browser
const result = await wfx.encrypt(fileInput.files[0]);
console.log(result.file_id);     // Use this ID to decrypt later
console.log(result.timing);      // { upload_ms, read_ms, encrypt_ms, store_ms }

// Node.js
const buffer = fs.readFileSync('secret-document.pdf');
const result = await wfx.encrypt(buffer, 'secret-document.pdf');
```

> [!NOTE]
> File uploads have **no timeout** — the SDK disables the AbortController timeout for FormData requests since large files (e.g., 3GB video) can take over an hour to upload. Regular JSON API calls still use the configured timeout.

**What's stored in YOUR database (not Wolfronix's):**
- Encrypted file blob (AES-256-GCM ciphertext — useless without the key)
- `key_part_a` — RSA encrypted with your public key (useless without your private key)
- `key_part_b` — RSA encrypted with server's public key (useless without server's private key)
- To decrypt: you need BOTH halves. Server alone can't. You alone can't.

---

## Workflow 4: Decrypt (Read) — Zero-Knowledge 3-Step Flow — Layers 4, 3, 2

This is the most important workflow. **Your private key NEVER leaves the browser.**

```
 BROWSER (SDK)                              WOLFRONIX ENGINE                    CLIENT'S DB
 ─────────────                              ────────────────                    ───────────

 ══ STEP 1: Fetch the encrypted key half ════════════════════════════════════════

     │  GET /api/v1/files/42/key
     │────────────────────────────────────────►│
     │                                         │  Fetch metadata ──────────────────►│
     │                                         │  ◄──────────────────────────────────│
     │◄────────────────────────────────────────│
     │  { key_part_a: "base64..." }
     │  (this is RSA-OAEP encrypted 16 bytes)
     │

 ══ STEP 2: Decrypt key_part_a CLIENT-SIDE ══════════════════════════════════════

     │  rsaDecryptBase64(key_part_a, this.privateKey)
     │  → RSA-OAEP decrypt using CryptoKey in browser memory
     │  → produces 16-byte cleartext → base64 encode
     │
     │  ⚠️ Private key used HERE, in browser RAM
     │     Never serialized. Never sent anywhere.
     │

 ══ STEP 3: Send decrypted half to server ═══════════════════════════════════════

     │  POST /api/v1/files/42/decrypt
     │  { decrypted_key_a: "base64...", user_role: "owner" }
     │  (only the 16-byte half — NOT the private key)
     │────────────────────────────────────────►│
     │                                         │
     │                                    ┌────┴──────────────────────────────────┐
     │                                    │  LAYER 4: DUAL-KEY RECONSTRUCTION    │
     │                                    │                                       │
     │                                    │  keyA = base64decode(decrypted_key_a) │
     │                                    │       → 16 bytes (from user)          │
     │                                    │                                       │
     │                                    │  keyB = RSA-OAEP decrypt(             │
     │                                    │    key_part_b,                        │
     │                                    │    Server Private Key                 │
     │                                    │  ) → 16 bytes (server's half)        │
     │                                    │                                       │
     │                                    │  fullKey = keyA + keyB → 32 bytes     │
     │                                    └────┬──────────────────────────────────┘
     │                                         │
     │                                         │  Fetch encrypted data ────────────►│
     │                                         │  ◄──────────────────────────────────│
     │                                         │
     │                                    ┌────┴──────────────────────────────────┐
     │                                    │  LAYER 3: AES-256-GCM DECRYPTION     │
     │                                    │                                       │
     │                                    │  nonce = ciphertext[0:12]             │
     │                                    │  data = ciphertext[12:]               │
     │                                    │  plaintext = AES-GCM.Open(           │
     │                                    │    nonce, data, fullKey               │
     │                                    │  )                                    │
     │                                    │  → also verifies integrity tag        │
     │                                    └────┬──────────────────────────────────┘
     │                                         │
     │                                    ┌────┴──────────────────────────────────┐
     │                                    │  LAYER 2: RBAC DYNAMIC MASKING       │
     │                                    │  (text files only: .txt, .csv, .json)│
     │                                    │                                       │
     │                                    │  Scans for:                           │
     │                                    │    PAN, Aadhaar, Credit Card,         │
     │                                    │    Email, Phone, SSN                  │
     │                                    │                                       │
     │                                    │  user_role="owner"  → see everything │
     │                                    │  user_role="analyst" → partial mask   │
     │                                    │  user_role="guest"  → all masked *** │
     │                                    └────┬──────────────────────────────────┘
     │                                         │
     │◄────────────────────────────────────────│
     │  Binary stream: decrypted (& masked) file
     │  Headers: Content-Disposition: attachment; filename="doc.pdf"
     │           X-Masking-Applied: owner
```

**SDK code:**
```typescript
// Browser — get as downloadable Blob
const blob = await wfx.decrypt('42', 'owner');
const url = URL.createObjectURL(blob);
window.open(url); // Download

// Node.js — get as ArrayBuffer
const buffer = await wfx.decryptToBuffer('42', 'analyst');
fs.writeFileSync('decrypted.pdf', Buffer.from(buffer));
```

---

## Workflow 5: List Files

```
 SDK                                        ENGINE                              CLIENT DB
 ───                                        ──────                              ─────────
     │  GET /api/v1/files                        │                                   │
     │  Headers: X-Wolfronix-Key, X-User-ID      │                                   │
     │───────────────────────────────────────────►│                                   │
     │                                            │  clientDBConn.ListFiles() ───────►│
     │                                            │  ◄───────────────────────────────│
     │◄───────────────────────────────────────────│                                   │
     │  [ { id, name, date, size_bytes, enc_time } ]
```

**SDK code:**
```typescript
const { files, total } = await wfx.listFiles();
files.forEach(f => console.log(f.original_name, f.file_id, f.encrypted_size));
```

---

## Workflow 6: Delete File

```
 SDK                                        ENGINE                              CLIENT DB
 ───                                        ──────                              ─────────
     │  DELETE /api/v1/files/42                   │                                   │
     │  Headers: X-Wolfronix-Key, X-User-ID      │                                   │
     │───────────────────────────────────────────►│                                   │
     │                                            │  clientDBConn.DeleteFile() ──────►│
     │                                            │  ◄───────────────────────────────│
     │                                            │  Update metrics (-1 file)         │
     │◄───────────────────────────────────────────│                                   │
     │  { success: true, message: "File deleted" }
```

**SDK code:**
```typescript
await wfx.deleteFile('42');
```

---

## Workflow 7: Server-Side Message Encryption (Dual-Key Split)

Unlike file encryption, message encryption works entirely over JSON — no file storage, no multipart uploads. The server handles AES key generation and optional dual-key split.

### Single Message Encrypt

```
 SDK                                        WOLFRONIX ENGINE
 ───                                        ────────────────
     │  POST /api/v1/messages/encrypt
     │  {
     │    "message": "Hello, this is secret!",
     │    "user_id": "user@email.com",
     │    "layer": 4                                    ← Layer 4 = dual-key split (default)
     │  }
     │──────────────────────────────────────────►│
     │                                           │  1. Generate 32-byte AES key (crypto/rand)
     │                                           │  2. AES-256-GCM encrypt(message, key)
     │                                           │  3. Split key:
     │                                           │     key_part_a = key[0:16]  → returned to client
     │                                           │     key_part_b = key[16:32] → stored in memory
     │                                           │     message_tag = unique ID → links to key_part_b
     │                                           │  4. Store { tag → key_part_b } in ephemeral store
     │                                           │     (24h TTL, auto-cleanup every 15 min)
     │◄──────────────────────────────────────────│
     │  {
     │    "encrypted_message": "base64...",
     │    "nonce": "base64...",
     │    "key_part_a": "base64...",       ← client's half (16 bytes)
     │    "message_tag": "msg-a1b2c3...",  ← lookup token for server's half
     │    "timestamp": 1707746400
     │  }
```

### Single Message Decrypt

```
 SDK                                        WOLFRONIX ENGINE
 ───                                        ────────────────
     │  POST /api/v1/messages/decrypt
     │  {
     │    "encrypted_message": "base64...",
     │    "nonce": "base64...",
     │    "key_part_a": "base64...",
     │    "message_tag": "msg-a1b2c3..."
     │  }
     │──────────────────────────────────────────►│
     │                                           │  1. Look up key_part_b by message_tag
     │                                           │  2. Verify clientID ownership
     │                                           │  3. Reconstruct: fullKey = keyA + keyB
     │                                           │  4. AES-256-GCM decrypt(ciphertext, fullKey)
     │◄──────────────────────────────────────────│
     │  {
     │    "message": "Hello, this is secret!",
     │    "timestamp": 1707746401
     │  }
```

### Batch Encrypt (up to 100 messages per request)

```
 SDK                                        WOLFRONIX ENGINE
 ───                                        ────────────────
     │  POST /api/v1/messages/batch/encrypt
     │  {
     │    "messages": [
     │      { "id": "msg1", "message": "Hello" },
     │      { "id": "msg2", "message": "World" },
     │      ...up to 100
     │    ],
     │    "layer": 4
     │  }
     │──────────────────────────────────────────►│
     │                                           │  1. Generate ONE AES key for batch
     │                                           │  2. Encrypt each message with UNIQUE nonce
     │                                           │     (4 random bytes + 8-byte counter)
     │                                           │  3. Split key: same dual-key pattern
     │◄──────────────────────────────────────────│
     │  {
     │    "results": [
     │      { "id": "msg1", "encrypted_message": "...", "nonce": "...", "seq": 0 },
     │      { "id": "msg2", "encrypted_message": "...", "nonce": "...", "seq": 1 }
     │    ],
     │    "key_part_a": "base64...",
     │    "batch_tag": "batch-x1y2z3..."
     │  }
```

**SDK code:**
```typescript
// Encrypt a single message
const result = await wfx.serverEncrypt('Hello secret world!');
// Store: result.encrypted_message, result.nonce, result.key_part_a, result.message_tag

// Decrypt it back
const plaintext = await wfx.serverDecrypt({
  encryptedMessage: result.encrypted_message,
  nonce: result.nonce,
  keyPartA: result.key_part_a,
  messageTag: result.message_tag,
});
// → "Hello secret world!"

// Batch encrypt
const batch = await wfx.serverEncryptBatch([
  { id: 'msg1', message: 'Hello' },
  { id: 'msg2', message: 'World' },
]);
// Decrypt one item from batch
const text = await wfx.serverDecryptBatchItem(batch, 0);
// → "Hello"
```

**Layer 3 mode** (no key split — full key returned to client):
```typescript
const result = await wfx.serverEncrypt('Hello', { layer: 3 });
// result.key_part_a = full 32-byte key (base64)
// result.message_tag = "" (no server half)
```

---

## Workflow 8: Real-Time Streaming Encryption (WebSocket)

For audio, video, live data — the engine encrypts/decrypts data in real-time over WebSocket. Each chunk is individually AES-256-GCM encrypted with counter-based nonces.

```
 SDK (WolfronixStream)                      WOLFRONIX ENGINE (WSS)
 ─────────────────────                      ──────────────────────

 ══ ENCRYPT DIRECTION ═══════════════════════════════════════════════

     │  1. WebSocket connect: wss://engine:5001/api/v1/stream
     │     Query params: wolfronix_key=wfx_xxx (browsers can't set WS headers)
     │────────────────────────────WSS────────►│
     │                                        │
     │  2. {"type":"init","direction":"encrypt"}
     │────────────────────────────────────────►│
     │                                        │  Generate AES-256 key
     │                                        │  Split: key_part_a → client, key_part_b → memory
     │◄────────────────────────────────────────│
     │  {"type":"init_ack",
     │   "key_part_a":"base64...",
     │   "stream_tag":"stream-a1b2c3..."}
     │
     │  3. Send data chunks:
     │  {"type":"data","data":"<base64 chunk>"}
     │────────────────────────────────────────►│
     │                                        │  nonce = [4 zero bytes + 8-byte counter]
     │                                        │  encrypted = AES-GCM.Seal(nonce, chunk)
     │◄────────────────────────────────────────│
     │  {"type":"data","data":"<base64 encrypted>","seq":0}
     │
     │  ... repeat for each chunk ...
     │
     │  4. {"type":"end"}
     │────────────────────────────────────────►│
     │◄────────────────────────────────────────│
     │  {"type":"end_ack","chunks_processed":N}

 ══ DECRYPT DIRECTION ═══════════════════════════════════════════════

     │  1. {"type":"init","direction":"decrypt",
     │       "key_part_a":"base64...","stream_tag":"stream-a1b2c3..."}
     │────────────────────────────────────────►│
     │                                        │  Look up key_part_b
     │                                        │  Reconstruct full key
     │◄────────────────────────────────────────│
     │  {"type":"init_ack"}
     │
     │  2. Send encrypted chunks → get decrypted chunks back
```

**SDK code:**
```typescript
// === ENCRYPT STREAM ===
const stream = await wfx.createStream('encrypt');

// Listen for encrypted chunks
stream.onData((encryptedChunk, seq) => {
  console.log(`Chunk ${seq} encrypted`);
  sendToRecipient(encryptedChunk); // e.g., via WebRTC
});

// Send plaintext chunks
await stream.send('audio data chunk 1...');
await stream.send('audio data chunk 2...');

// Or send binary data
const audioBuffer = new Uint8Array([...]);
await stream.sendBinary(audioBuffer);

// End session
const summary = await stream.end();
console.log(`Processed ${summary.chunksProcessed} chunks`);

// Save these for decryption:
const { keyPartA, streamTag } = stream;

// === DECRYPT STREAM ===
const dStream = await wfx.createStream('decrypt', {
  keyPartA: keyPartA!,
  streamTag: streamTag!,
});

dStream.onData((decryptedChunk, seq) => {
  playAudio(decryptedChunk); // decrypted data
});

// Feed encrypted chunks back
await dStream.send(encryptedChunk1);
await dStream.send(encryptedChunk2);
await dStream.end();
```

---

## Workflow 9: E2E Chat Messages (Client-Side Only)

The SDK also supports pure **end-to-end encrypted messaging** between two users using hybrid RSA+AES — the server never sees plaintext:

```
 SENDER SDK                                                     RECIPIENT SDK
 ──────────                                                     ─────────────
     │                                                                │
     │  1. getPublicKey(recipientId)                                  │
     │     → GET /api/v1/keys/public/{clientID}/{recipientId}        │
     │     → returns recipient's public_key_pem                       │
     │                                                                │
     │  2. generateSessionKey() → random AES-256 key                  │
     │  3. encryptData(message, sessionKey) → { encrypted, iv }       │
     │  4. rsaEncrypt(sessionKey, recipientPublicKey)                  │
     │  5. Pack into JSON: { key, iv, msg }                           │
     │                                                                │
     │  ───── send JSON packet via your chat system ─────────────────►│
     │                                                                │
     │                                    6. rsaDecrypt(packet.key, myPrivateKey)
     │                                       → recover AES session key
     │                                    7. importSessionKey(rawKey)
     │                                    8. decryptData(packet.msg, packet.iv, sessionKey)
     │                                       → original message
```

**SDK code:**
```typescript
// Sender
const packet = await wfx.encryptMessage('Hello secret!', 'recipient@email.com');
// Send `packet` string via your chat/websocket

// Recipient
const plaintext = await wfx.decryptMessage(packet);
// → "Hello secret!"
```

---

## How the SaaS Platform Fits In

The **Wolfronix SaaS** (`Wolfronix_saas/`) is a separate Node.js app that wraps the core engine for self-service:

```
 USER BROWSER                    SaaS BACKEND (Node.js)              WOLFRONIX ENGINE
 ────────────                    ──────────────────────              ────────────────
     │                                   │                                  │
     │  1. POST /api/auth/register       │                                  │
     │  { email, password, name }        │                                  │
     │──────────────────────────────────►│                                  │
     │                                   │  Create user in Prisma/PG        │
     │                                   │  Hash password (bcrypt)          │
     │                                   │  Return JWT                      │
     │◄──────────────────────────────────│                                  │
     │                                   │                                  │
     │  2. POST /api/subscription/create │                                  │
     │  { plan: "PRO" }                  │                                  │
     │──────────────────────────────────►│                                  │
     │                                   │  Create subscription via         │
     │                                   │  Razorpay (payment gateway)      │
     │◄──────────────────────────────────│                                  │
     │                                   │                                  │
     │  3. POST /api/wolfronix/key       │                                  │
     │  (Generate API Key)               │                                  │
     │──────────────────────────────────►│                                  │
     │                                   │  a. generateWolfronixKey()       │
     │                                   │     → "wfx_<random>"             │
     │                                   │                                  │
     │                                   │  b. POST /api/v1/enterprise/register
     │                                   │     X-Admin-Key: <ADMIN_KEY>     │
     │                                   │     { client_id: "saas_42",      │
     │                                   │       wolfronix_key: "wfx_...",  │
     │                                   │       plan: "PRO",               │
     │                                   │       api_calls_limit: 100000 }  │
     │                                   │─────────────────────────────────►│
     │                                   │                                  │  Register in
     │                                   │                                  │  client_registry
     │                                   │◄─────────────────────────────────│
     │                                   │                                  │
     │                                   │  c. Save to SaaS DB:             │
     │                                   │     wolfronixApiKey = "wfx_..."  │
     │                                   │     wolfronixClientId= "saas_42" │
     │◄──────────────────────────────────│                                  │
     │  { apiKey: "wfx_...",             │                                  │
     │    clientId: "saas_42" }          │                                  │
     │                                   │                                  │
     │  4. Now user configures the SDK:  │                                  │
     │                                   │                                  │
     │  const wfx = new Wolfronix({      │                                  │
     │    baseUrl: 'https://engine:5002',│                                  │
     │    clientId: 'saas_42',           │                                  │
     │    wolfronixKey: 'wfx_...'        │                                  │
     │  });                              │                                  │
     │                                   │                                  │
     │  SDK talks directly to engine ────│─────────────────────────────────►│
     │  (SaaS is NOT in the data path)   │                                  │
```

### API Key Revocation Flow

When a SaaS user revokes their key, the SaaS backend deactivates the client on the engine:

```
 SaaS BACKEND                               WOLFRONIX ENGINE
 ────────────                               ────────────────
     │
     │  1. DELETE /api/v1/enterprise/clients/{clientID}
     │     Headers: X-Admin-Key: <ADMIN_KEY>
     │──────────────────────────────────────────►│
     │                                           │  Set is_active = false
     │                                           │  in client_registry
     │◄──────────────────────────────────────────│
     │
     │  2. Prisma: set wolfronixApiKey = null
     │     wolfronixClientId = null
     │
     │  Result: Client's X-Wolfronix-Key immediately
     │  stops working (middleware checks is_active)
```

**Key point:** The SaaS platform handles **billing, auth, and key provisioning**. Once the user has their `wolfronixKey` and `clientId`, the SDK talks **directly** to the Go engine. The SaaS app is never in the encryption/decryption data path.

---

## Complete API Endpoint Reference

### Core File Encryption

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/encrypt` | X-Wolfronix-Key | Encrypt + store a file (multipart/form-data) |
| GET | `/api/v1/files` | X-Wolfronix-Key | List all user's encrypted files |
| GET | `/api/v1/files/{id}/key` | X-Wolfronix-Key | Fetch encrypted key_part_a for a file |
| POST | `/api/v1/files/{id}/decrypt` | X-Wolfronix-Key | Decrypt a file (zero-knowledge flow) |
| DELETE | `/api/v1/files/{id}` | X-Wolfronix-Key | Delete an encrypted file |

### Message Encryption

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/messages/encrypt` | X-Wolfronix-Key | Encrypt a text message (JSON in/out) |
| POST | `/api/v1/messages/decrypt` | X-Wolfronix-Key | Decrypt a text message |
| POST | `/api/v1/messages/batch/encrypt` | X-Wolfronix-Key | Batch encrypt up to 100 messages |

### Real-Time Streaming

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET (WebSocket) | `/api/v1/stream` | `wolfronix_key` query param | Real-time chunk encrypt/decrypt over WSS |

### Key Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/keys` | None | Get server's public key (PEM) |
| GET | `/api/v1/keys/{userId}` | X-Wolfronix-Key | Get user's public key |
| POST | `/api/v1/keys/register` | X-Wolfronix-Key | Register user keys (zero-knowledge) |
| POST | `/api/v1/keys/login` | X-Wolfronix-Key | Fetch wrapped keys for login |
| GET | `/api/v1/keys/public/{clientID}/{userID}` | X-Wolfronix-Key | Get any user's public key |

### Enterprise (Admin Only)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/enterprise/register` | X-Admin-Key | Register a new enterprise client |
| GET | `/api/v1/enterprise/clients` | X-Admin-Key | List all registered clients |
| GET | `/api/v1/enterprise/clients/{id}` | X-Admin-Key | Get client details |
| PUT | `/api/v1/enterprise/clients/{id}` | X-Admin-Key | Update client config (URL validated) |
| DELETE | `/api/v1/enterprise/clients/{id}` | X-Admin-Key | Deactivate (revoke) a client |

### Metrics

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/metrics/summary` | X-Wolfronix-Key | Overall metrics summary |
| GET | `/api/v1/metrics/clients` | X-Wolfronix-Key | All client metrics |
| GET | `/api/v1/metrics/client/{id}` | X-Wolfronix-Key | Specific client metrics |
| GET | `/api/v1/metrics/client/{id}/stats` | X-Wolfronix-Key | Client stats (time range) |
| POST | `/api/v1/metrics/users` | X-Wolfronix-Key | Add user |
| DELETE | `/api/v1/metrics/users` | X-Wolfronix-Key | Remove user |
| POST | `/api/v1/metrics/login` | X-Wolfronix-Key | Record user login |

### Utility

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | None | Health check |

---

## Authentication Flow Summary

| Layer | Mechanism | What authenticates |
|-------|----------|-------------------|
| **SDK → Engine** | `X-Wolfronix-Key` header | Every API request — the engine's `apiKeyAuthMiddleware` validates against `client_registry` and sets `X-Authenticated-Client-ID` |
| **SDK → Engine** | `getAuthenticatedClientID()` | Every handler verifies the authenticated client ID matches any caller-supplied `X-Client-ID` — prevents client impersonation |
| **SDK → Engine (WS)** | `wolfronix_key` query param | WebSocket connections — browsers can't set custom headers on WS upgrades |
| **User → SDK** | Password (PBKDF2 → AES-GCM unwrap) | Login: if the password is wrong, the private key unwrap fails (AES-GCM tag mismatch) — server never validates or sees the password |
| **SaaS → Engine** | `X-Admin-Key` header | Enterprise endpoints (`/api/v1/enterprise/*`) — admin-only |
| **SaaS → User** | JWT token (bcrypt-verified) | SaaS platform's own auth for dashboard, billing, settings |

---

## Complete SDK API Reference (v2.4.1)

### Installation

```bash
# Node.js / bundler
npm install wolfronix-sdk

# Browser (no bundler) — IIFE bundle
# Build: cd sdk/javascript && npm run build:browser
# Copy: dist/index.global.js → your project as wolfronix.browser.js
# Usage: <script src="wolfronix.browser.js"></script>
#        → exposes window.WolfronixSDK
```

```typescript
const wfx = new Wolfronix({
  baseUrl: 'https://engine:5002',   // Wolfronix Go engine URL
  clientId: 'your-client-id',       // From SaaS or manual setup
  wolfronixKey: 'wfx_your-key',     // API key for X-Wolfronix-Key
  timeout: 30000,                    // Request timeout (ms) — file uploads bypass this
  retries: 3,                        // Auto-retry with exponential backoff
  insecure: false                    // Set true for self-signed certs (dev only)
});

// ── Auth ──
await wfx.register(email, password);     // Generate keys + register
await wfx.login(email, password);        // Fetch + unwrap keys
wfx.logout();                            // Clear keys from memory
wfx.isAuthenticated();                   // Check session status
wfx.getUserId();                         // Get current user ID

// ── File Operations ──
await wfx.encrypt(file, filename?);        // Encrypt + store → { file_id, timing, ... }
await wfx.decrypt(fileId, role?);          // Zero-knowledge decrypt → Blob
await wfx.decryptToBuffer(fileId, role?);  // Zero-knowledge decrypt → ArrayBuffer
await wfx.getFileKey(fileId);              // Get encrypted key_part_a
await wfx.listFiles();                     // List all user's files
await wfx.deleteFile(fileId);              // Delete encrypted file

// ── Server-Side Message Encryption ──
await wfx.serverEncrypt(message, { layer?: 3|4 });  // Encrypt text → dual-key result
await wfx.serverDecrypt({ encryptedMessage, nonce, keyPartA, messageTag? }); // Decrypt
await wfx.serverEncryptBatch(messages[], { layer?: 3|4 });  // Batch encrypt ≤100
await wfx.serverDecryptBatchItem(batchResult, index);       // Decrypt one batch item

// ── Real-Time Streaming (WebSocket) ──
const stream = await wfx.createStream('encrypt');  // → WolfronixStream
stream.onData((chunk, seq) => { ... });            // Listen for processed chunks
stream.onError((err) => { ... });                  // Handle errors
await stream.send('plaintext data');               // Send text chunk
await stream.sendBinary(uint8Array);               // Send binary chunk
const summary = await stream.end();                // End stream → { chunksProcessed }
// stream.keyPartA / stream.streamTag — save for decrypt session

const dStream = await wfx.createStream('decrypt', { keyPartA, streamTag });
await dStream.send(encryptedChunk);
await dStream.end();

// ── E2E Client-Side Messaging ──
await wfx.encryptMessage(text, recipientId);   // Hybrid RSA+AES → JSON packet
await wfx.decryptMessage(packetJson);          // Decrypt received packet

// ── Utility ──
await wfx.getPublicKey(userId, clientId?);   // Get any user's public key
await wfx.getMetrics();                      // Encryption/decryption stats
await wfx.healthCheck();                     // Server health check
```

---

## Security Guarantees

1. **Zero-Knowledge**: Wolfronix engine never sees raw private keys or unencrypted file content (only encrypted blobs and ciphertext pass through)
2. **Dual-Key Split**: Neither the user alone nor the server alone can decrypt — both halves required (files AND messages in Layer 4)
3. **Password = Proof**: Wrong password → AES-GCM tag mismatch → can't unwrap private key → can't decrypt anything
4. **Client Impersonation Prevention**: `getAuthenticatedClientID()` enforces that the middleware-verified identity matches any caller-supplied `X-Client-ID` — client A cannot act as client B
5. **RBAC at Decrypt Time**: Masking is applied AFTER decryption, meaning even with valid access, sensitive fields are hidden based on role
6. **Client-Side Storage**: Encrypted files live in YOUR database, not Wolfronix's servers
7. **TLS + API Key**: All traffic over HTTPS; every request authenticated with `X-Wolfronix-Key`; WebSocket uses `wolfronix_key` query param (since browsers can't set custom WS headers)
8. **Ephemeral Message Keys**: Server-held message key halves auto-expire after 24 hours (configurable)
9. **Counter-Based Nonces**: Streaming uses deterministic 12-byte nonces (4 zeros + 8-byte counter) — guaranteed unique per stream session, no collision risk
10. **SSRF Protection**: Enterprise client URL updates validated (scheme must be http/https, host must be non-empty)

---

## Docker Deployment

### Quick Start (Development)

```bash
# 1. Create .env file
cat > .env << 'EOF'
DB_PASSWORD=your-strong-db-password
ADMIN_API_KEY=your-admin-secret-key
EOF

# 2. Start everything
docker compose up -d

# 3. Verify health
curl -k https://localhost:5002/health
# → {"status":"healthy","timestamp":"..."}

# 4. Test message encryption
curl -k https://localhost:5002/api/v1/messages/encrypt \
  -H "X-Wolfronix-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"message":"Hello","user_id":"test","layer":4}'
```

### Production Deployment

```bash
# 1. Create production .env
cat > .env << 'EOF'
DB_PASSWORD=<strong-random-password>
ADMIN_API_KEY=<strong-random-admin-key>
JWT_SECRET=<strong-random-jwt-secret>
MASTER_KEY=<strong-random-master-key>
DATA_PATH=/opt/wolfronix/data
EOF

# 2. Deploy with production compose
cd deploy/
docker compose -f docker-compose.prod.yml up -d

# Architecture:
#   nginx (9443) → wolfronix engine (5001) → postgres (5432)
#   5 managed DB connectors (supabase, mongodb, mysql, firebase, postgresql)
#   mock_db for local testing (filesystem-based, 4 gunicorn workers)
#   Certbot handles SSL renewal automatically
#   WebSocket proxied via nginx (Connection: Upgrade)
```

### Managed Database Connectors

The engine auto-routes encrypted file storage to the correct connector based on each client's `db_type`:

| Connector | Port | Description |
|-----------|------|-------------|
| `connector_supabase` | 4001 | Supabase storage (S3-compatible) |
| `connector_mongodb` | 4002 | MongoDB GridFS |
| `connector_mysql` | 4003 | MySQL BLOB storage |
| `connector_firebase` | 4004 | Firebase Cloud Storage |
| `connector_postgresql` | 4005 | PostgreSQL BYTEA/lo storage |
| `mock_db` | 4000 | Local filesystem (Flask + gunicorn, for testing) |

> [!NOTE]
> The mock_db service uses a **file-based atomic counter** (`mock_storage/counter.txt`) with `fcntl` file locking to generate unique file IDs across all 4 gunicorn workers and container restarts.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_HOST` | Yes | `postgres` | PostgreSQL hostname |
| `DB_PORT` | No | `5432` | PostgreSQL port |
| `DB_USER` | Yes | `admin` | PostgreSQL username |
| `DB_PASS` | Yes | — | PostgreSQL password |
| `DB_NAME` | Yes | `client_vault` | PostgreSQL database name |
| `ADMIN_API_KEY` | Yes | — | Admin key for enterprise endpoints |
| `JWT_SECRET` | Yes | — | JWT signing secret |
| `MASTER_KEY` | Yes | — | Master encryption key |
| `ALLOWED_ORIGINS` | No | `*` | CORS allowed origins (comma-separated) |
| `CLIENT_DB_API_ENDPOINT` | No | — | Client's DB API URL (enterprise mode) |
| `CLIENT_DB_API_KEY` | No | — | Client's DB API key |
| `CLIENT_DB_TYPE` | No | `custom_api` | Client DB connector type |
| `CLIENT_DB_TIMEOUT` | No | `30s` | Client DB request timeout |
| `CLIENT_DB_RETRY_COUNT` | No | `3` | Client DB retry count |
| `GOGC` | No | `50` | Go GC target percentage |
| `GOMEMLIMIT` | No | `6GiB` | Go memory limit |

### Ports

| Service | Internal Port | Default External Port | Protocol |
|---------|--------------|----------------------|----------|
| Wolfronix Engine | 5001 | 5002 (dev), 9443 (prod via nginx) | HTTPS + WSS |
| PostgreSQL | 5432 | 5433 (dev only) | TCP |
| Nginx | 80/443 | 9080/9443 (prod) | HTTP/HTTPS |
| Mock DB | 4000 | internal only | HTTP |
| Supabase Connector | 4001 | internal only | HTTP |
| MongoDB Connector | 4002 | internal only | HTTP |
| MySQL Connector | 4003 | internal only | HTTP |
| Firebase Connector | 4004 | internal only | HTTP |
| PostgreSQL Connector | 4005 | internal only | HTTP |
| Redis | 6379 | internal only | TCP |

### Rebuilding the SDK Browser Bundle

After making changes to the SDK source, rebuild the browser IIFE bundle:

```bash
cd sdk/javascript
npm run build:browser          # → dist/index.global.js (419KB)
cp dist/index.global.js ../../test_app/wolfronix.browser.js
```

The bundle exposes `window.WolfronixSDK` for direct use in HTML `<script>` tags (no bundler needed).

### Publishing the SDK to npm

```bash
cd sdk/javascript
npm login
npm publish --access public    # publishes as wolfronix-sdk@<version>
```
