# Wolfronix Complete Guide

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [API Endpoints Reference](#api-endpoints-reference)
4. [Workflows](#workflows)
   - [User Registration](#1-user-registration-workflow)
   - [User Login](#2-user-login-workflow)
   - [File Encryption](#3-file-encryption-workflow)
   - [File Decryption](#4-file-decryption-workflow)
   - [File Listing](#5-file-listing-workflow)
   - [File Delete](#6-file-delete-workflow)
   - [Enterprise Client Setup](#7-enterprise-client-setup-workflow)
5. [Storage Modes](#storage-modes)
6. [Security Layers](#security-layers)

---

## System Overview

**Wolfronix** is a 4-layer zero-knowledge encryption engine that processes sensitive data without ever seeing the original content.

| Component | Technology | Purpose |
|-----------|------------|---------|
| Backend | Go 1.22 | Processing engine |
| Database | PostgreSQL 15 | Metadata storage |
| Protocol | HTTPS (TLS) | Secure transport |
| Port | 5002 (external) → 5001 (internal) | API access |

**Base URL:** `https://localhost:5002`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT APPLICATION                        │
│                    (Web App / Mobile / Desktop)                  │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ HTTPS
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      WOLFRONIX ENGINE                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Layer 1:     │  │ Layer 2:     │  │ Layer 3:             │   │
│  │ Fake Data    │→ │ Key Wrapping │→ │ AES-256-GCM          │   │
│  │ Masking      │  │ (Per-User)   │  │ Encryption           │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
│                                              │                   │
│                                              ▼                   │
│                              ┌──────────────────────────────┐   │
│                              │ Layer 4: Chunked Streaming   │   │
│                              │ (5MB chunks, parallel)       │   │
│                              └──────────────────────────────┘   │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
┌──────────────────────┐                    ┌──────────────────────┐
│   SELF-HOSTED MODE   │                    │   ENTERPRISE MODE    │
│   (Wolfronix DB)     │                    │   (Client's API)     │
│                      │                    │                      │
│ • All data stored    │                    │ • Metadata only in   │
│   locally            │                    │   Wolfronix          │
│ • Demo/Testing       │                    │ • User data in       │
│                      │                    │   Client's DB        │
└──────────────────────┘                    └──────────────────────┘
```

---

## API Endpoints Reference

### Authentication Endpoints
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/keys/register` | Register new user |
| POST | `/api/v1/keys/login` | User login |

### File Operations
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/encrypt` | Encrypt and store file |
| GET | `/api/v1/files/{id}/key` | Get encrypted key_part_a (Step 1 of zero-knowledge decrypt) |
| POST | `/api/v1/files/{id}/decrypt` | Decrypt file with decrypted_key_a (Step 2+3 of zero-knowledge decrypt) |
| GET | `/api/v1/files` | List user's files |
| DELETE | `/api/v1/files/{id}` | Delete a file |

### Streaming (Large Files)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/stream` | WebSocket endpoint (upgrade to ws) — supports stream token, encrypt, and decrypt operations |

### Enterprise Management
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/enterprise/register` | Register client |
| GET | `/api/v1/enterprise/clients` | List all clients |
| GET | `/api/v1/enterprise/clients/{id}` | Get client details |
| PUT | `/api/v1/enterprise/clients/{id}` | Update client |

### Metrics & Admin
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/metrics` | Get encryption metrics |
| GET | `/api/v1/admin/metrics` | Detailed admin metrics |

---

## Workflows

### 1. User Registration Workflow

```
┌──────────┐         ┌─────────────┐         ┌──────────┐
│  Client  │         │  Wolfronix  │         │    DB    │
└────┬─────┘         └──────┬──────┘         └────┬─────┘
     │                      │                     │
     │  POST /register      │                     │
     │  {email, password}   │                     │
     │─────────────────────>│                     │
     │                      │                     │
     │                      │  Hash password      │
     │                      │  (bcrypt)           │
     │                      │                     │
     │                      │  Generate user_id   │
     │                      │  (UUID)             │
     │                      │                     │
     │                      │  INSERT user        │
     │                      │────────────────────>│
     │                      │                     │
     │                      │  Generate wrapped   │
     │                      │  key for user       │
     │                      │────────────────────>│
     │                      │                     │
     │  {user_id, token}    │                     │
     │<─────────────────────│                     │
     │                      │                     │
```

**Request:**
```http
POST /api/v1/keys/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "success": true,
  "user_id": "uuid-here",
  "token": "jwt-token-here",
  "message": "Registration successful"
}
```

**What Happens:**
1. Password hashed with bcrypt
2. Unique user_id (UUID) generated
3. User record created in `users` table
4. Per-user encryption key generated and wrapped
5. Wrapped key stored (local or client API based on mode)
6. JWT token returned for authentication

---

### 2. User Login Workflow

```
┌──────────┐         ┌─────────────┐         ┌──────────┐
│  Client  │         │  Wolfronix  │         │    DB    │
└────┬─────┘         └──────┬──────┘         └────┬─────┘
     │                      │                     │
     │  POST /login         │                     │
     │  {email, password}   │                     │
     │─────────────────────>│                     │
     │                      │                     │
     │                      │  SELECT user        │
     │                      │────────────────────>│
     │                      │<────────────────────│
     │                      │                     │
     │                      │  Verify password    │
     │                      │  (bcrypt compare)   │
     │                      │                     │
     │                      │  Generate JWT       │
     │                      │  (24hr expiry)      │
     │                      │                     │
     │  {user_id, token}    │                     │
     │<─────────────────────│                     │
     │                      │                     │
```

**Request:**
```http
POST /api/v1/keys/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "success": true,
  "user_id": "uuid-here",
  "token": "jwt-token-here",
  "message": "Login successful"
}
```

**What Happens:**
1. Find user by email
2. Compare password hash with bcrypt
3. If valid, generate JWT token (24hr expiry)
4. Return user_id and token

---

### 3. File Encryption Workflow

```
┌──────────┐         ┌─────────────┐         ┌──────────┐         ┌────────────┐
│  Client  │         │  Wolfronix  │         │ Local DB │         │ Client API │
└────┬─────┘         └──────┬──────┘         └────┬─────┘         └─────┬──────┘
     │                      │                     │                     │
     │  POST /encrypt       │                     │                     │
     │  (multipart form)    │                     │                     │
     │─────────────────────>│                     │                     │
     │                      │                     │                     │
     │                      │ ┌─────────────────────────────────────┐   │
     │                      │ │ LAYER 1: Fake Data Masking          │   │
     │                      │ │ - Generate decoy data               │   │
     │                      │ │ - Mix with padding                  │   │
     │                      │ └─────────────────────────────────────┘   │
     │                      │                     │                     │
     │                      │ ┌─────────────────────────────────────┐   │
     │                      │ │ LAYER 2: Key Wrapping               │   │
     │                      │ │ - Get/create user's wrapped key     │   │
     │                      │ │ - Unwrap with master key            │   │
     │                      │ └─────────────────────────────────────┘   │
     │                      │                     │                     │
     │                      │ ┌─────────────────────────────────────┐   │
     │                      │ │ LAYER 3: AES-256-GCM Encryption     │   │
     │                      │ │ - Generate random nonce             │   │
     │                      │ │ - Encrypt with user's key           │   │
     │                      │ └─────────────────────────────────────┘   │
     │                      │                     │                     │
     │                      │ ┌─────────────────────────────────────┐   │
     │                      │ │ LAYER 4: Chunked Storage            │   │
     │                      │ │ - Split into 5MB chunks             │   │
     │                      │ │ - Store chunks                      │   │
     │                      │ └─────────────────────────────────────┘   │
     │                      │                     │                     │
     │                      │  Check storage mode │                     │
     │                      │─────────────────────│                     │
     │                      │                     │                     │
     │                      │  [SELF-HOSTED]      │                     │
     │                      │  Store locally      │                     │
     │                      │────────────────────>│                     │
     │                      │                     │                     │
     │                      │  [ENTERPRISE]       │                     │
     │                      │  POST to client API─│────────────────────>│
     │                      │                     │                     │
     │                      │                     │                     │
     │  {file_id, status}   │                     │                     │
     │<─────────────────────│                     │                     │
     │                      │                     │                     │
```

**Request:**
```http
POST /api/v1/encrypt
Authorization: Bearer <jwt-token>
Content-Type: multipart/form-data
X-Client-ID: client-uuid (optional, for enterprise)

file: <binary data>
user_id: uuid-here
```

**Response:**
```json
{
  "success": true,
  "file_id": "file-uuid-here",
  "original_name": "document.pdf",
  "encrypted_size": 1048576,
  "message": "File encrypted and stored successfully"
}
```

**What Happens:**
1. **Layer 1** - Generate fake decoy data
2. **Layer 2** - Retrieve/create user's wrapped key, unwrap it
3. **Layer 3** - Encrypt file with AES-256-GCM
4. **Layer 4** - Chunk into 5MB pieces for large files
5. **Storage Decision:**
   - If `X-Client-ID` present and registered → Send to Client's API
   - Otherwise → Store locally in Wolfronix DB
6. Record encryption metrics
7. Return file_id for retrieval

---

### 4. File Decryption Workflow (Zero-Knowledge 3-Step Flow)

The private key **NEVER** leaves the client. Instead, the SDK performs a 3-step protocol:

```
┌──────────┐         ┌─────────────┐                    ┌────────────┐
│  Client  │         │  Wolfronix  │                    │ Client API │
│  (SDK)   │         │   Engine    │                    │  (DB)      │
└────┬─────┘         └──────┬──────┘                    └─────┬──────┘
     │                      │                                 │
     │  ═══ STEP 1: Fetch Encrypted Key Half ═══              │
     │                      │                                 │
     │  GET /files/{id}/key │                                 │
     │  X-Wolfronix-Key     │                                 │
     │─────────────────────>│                                 │
     │                      │  Fetch file metadata            │
     │                      │────────────────────────────────>│
     │                      │<────────────────────────────────│
     │                      │                                 │
     │  {key_part_a: "..."}│  (RSA-OAEP encrypted            │
     │  (encrypted blob)    │   16-byte key half)             │
     │<─────────────────────│                                 │
     │                      │                                 │
     │  ═══ STEP 2: Client-Side Decryption (LOCAL) ═══        │
     │                      │                                 │
     │  ┌──────────────────────────────────┐                  │
     │  │ RSA-OAEP decrypt key_part_a      │                  │
     │  │ using Private Key (in memory)    │                  │
     │  │ → produces 16-byte cleartext     │                  │
     │  │ → base64-encode result           │                  │
     │  │                                  │                  │
     │  │ ⚠️  Private Key stays HERE       │                  │
     │  │    Never sent to any server!     │                  │
     │  └──────────────────────────────────┘                  │
     │                      │                                 │
     │  ═══ STEP 3: Send Decrypted Key Half to Server ═══     │
     │                      │                                 │
     │  POST /files/{id}/decrypt                              │
     │  {decrypted_key_a,   │                                 │
     │   user_role}         │                                 │
     │─────────────────────>│                                 │
     │                      │                                 │
     │                      │ ┌─────────────────────────────────────┐
     │                      │ │ LAYER 4: Dual-Key Reconstruction    │
     │                      │ │ - keyA = base64decode(decrypted_    │
     │                      │ │         key_a) → 16 bytes           │
     │                      │ │ - keyB = RSA decrypt key_part_b     │
     │                      │ │         with Server Private Key     │
     │                      │ │         → 16 bytes                  │
     │                      │ │ - fullKey = keyA + keyB (32 bytes)  │
     │                      │ └─────────────────────────────────────┘
     │                      │                                 │
     │                      │  Fetch encrypted data           │
     │                      │────────────────────────────────>│
     │                      │<────────────────────────────────│
     │                      │                                 │
     │                      │ ┌─────────────────────────────────────┐
     │                      │ │ LAYER 3: AES-256-GCM Decryption    │
     │                      │ │ - Extract nonce (first 12 bytes)   │
     │                      │ │ - Decrypt with fullKey (32-byte)   │
     │                      │ │ - Verify authentication tag        │
     │                      │ └─────────────────────────────────────┘
     │                      │                                 │
     │                      │ ┌─────────────────────────────────────┐
     │                      │ │ LAYER 2: RBAC Dynamic Masking      │
     │                      │ │ - If text file (.txt/.csv/.json):  │
     │                      │ │   mask sensitive fields by role    │
     │                      │ │ - owner: full access               │
     │                      │ │ - analyst: partial masking         │
     │                      │ │ - guest: heavy masking             │
     │                      │ └─────────────────────────────────────┘
     │                      │                                 │
     │  <decrypted file>    │                                 │
     │  (masked by role)    │                                 │
     │<─────────────────────│                                 │
     │                      │                                 │
```

**Step 1 — Fetch Encrypted Key Half:**
```http
GET /api/v1/files/123/key
X-Wolfronix-Key: <api-key>
X-Client-ID: client-uuid
X-User-ID: user-uuid
```

**Step 1 Response:**
```json
{
  "file_id": "123",
  "key_part_a": "<RSA-OAEP encrypted 16-byte key half, base64>",
  "message": "Decrypt key_part_a locally with your private key..."
}
```

**Step 2 — Client-Side (SDK does this automatically):**
```typescript
// SDK internally does:
const decryptedKeyA = await rsaDecryptBase64(keyResponse.key_part_a, this.privateKey);
// privateKey is a CryptoKey in browser memory — never serialized or sent
```

**Step 3 — Decrypt with key half:**
```http
POST /api/v1/files/123/decrypt
X-Wolfronix-Key: <api-key>
X-Client-ID: client-uuid
Content-Type: application/json

{
  "decrypted_key_a": "<base64-encoded 16-byte cleartext key half>",
  "user_role": "owner"
}
```

**Step 3 Response:**
```
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="document.pdf"
X-Masking-Applied: owner

<binary file data — RBAC-masked if text>
```

**What Happens (server-side on Step 3):**
1. Base64-decode `decrypted_key_a` → 16-byte keyA (client's half)
2. RSA-OAEP decrypt `key_part_b` with Server Private Key → 16-byte keyB (server's half)
3. **Layer 4** — Reconstruct full 32-byte AES key: `fullKey = keyA || keyB`
4. Fetch encrypted data from Client API via `clientDBConn`
5. **Layer 3** — AES-256-GCM authenticated decryption (extract nonce, decrypt, verify tag)
6. **Layer 2** — Apply RBAC dynamic masking on text files based on `user_role`
7. Record decryption metrics
8. Stream decrypted (and masked) file to client

> **Security Guarantee:** The client's RSA private key never touches the network. Only a 16-byte
> symmetric key half (which is useless without the server's 16-byte half) is transmitted over TLS.
> Neither party alone can decrypt the data — both halves are required.

---

### 5. File Listing Workflow

```
┌──────────┐         ┌─────────────┐         ┌──────────┐         ┌────────────┐
│  Client  │         │  Wolfronix  │         │ Local DB │         │ Client API │
└────┬─────┘         └──────┬──────┘         └────┬─────┘         └─────┬──────┘
     │                      │                     │                     │
     │  GET /files          │                     │                     │
     │  Authorization: JWT  │                     │                     │
     │─────────────────────>│                     │                     │
     │                      │                     │                     │
     │                      │  Extract user_id    │                     │
     │                      │  from JWT           │                     │
     │                      │                     │                     │
     │                      │  Check storage mode │                     │
     │                      │─────────────────────│                     │
     │                      │                     │                     │
     │                      │  [SELF-HOSTED]      │                     │
     │                      │  SELECT files       │                     │
     │                      │  WHERE user_id=?    │                     │
     │                      │<───────────────────>│                     │
     │                      │                     │                     │
     │                      │  [ENTERPRISE]       │                     │
     │                      │  GET /files?user_id │                     │
     │                      │<────────────────────│────────────────────>│
     │                      │                     │                     │
     │                      │                     │                     │
     │  [{file_id, name,    │                     │                     │
     │    size, date}, ...] │                     │                     │
     │<─────────────────────│                     │                     │
     │                      │                     │                     │
```

**Request:**
```http
GET /api/v1/files
Authorization: Bearer <jwt-token>
X-Client-ID: client-uuid (optional)
```

**Response:**
```json
{
  "success": true,
  "files": [
    {
      "file_id": "uuid-1",
      "original_name": "document.pdf",
      "encrypted_size": 1048576,
      "created_at": "2026-02-06T10:30:00Z"
    },
    {
      "file_id": "uuid-2",
      "original_name": "image.png",
      "encrypted_size": 524288,
      "created_at": "2026-02-06T11:00:00Z"
    }
  ],
  "total": 2
}
```

**What Happens:**
1. Extract user_id from JWT
2. Determine storage mode
3. Query files belonging to user only (isolation)
4. Return file metadata list

---

### 6. File Delete Workflow

```
┌──────────┐         ┌─────────────┐         ┌──────────┐         ┌────────────┐
│  Client  │         │  Wolfronix  │         │ Local DB │         │ Client API │
└────┬─────┘         └──────┬──────┘         └────┬─────┘         └─────┬──────┘
     │                      │                     │                     │
     │  DELETE /files/{id}  │                     │                     │
     │  Authorization: JWT  │                     │                     │
     │─────────────────────>│                     │                     │
     │                      │                     │                     │
     │                      │  Verify ownership   │                     │
     │                      │  (user_id match)    │                     │
     │                      │                     │                     │
     │                      │  Check storage mode │                     │
     │                      │─────────────────────│                     │
     │                      │                     │                     │
     │                      │  [SELF-HOSTED]      │                     │
     │                      │  DELETE from DB     │                     │
     │                      │  Remove file chunks │                     │
     │                      │────────────────────>│                     │
     │                      │                     │                     │
     │                      │  [ENTERPRISE]       │                     │
     │                      │  DELETE from client │                     │
     │                      │─────────────────────│────────────────────>│
     │                      │                     │                     │
     │                      │                     │                     │
     │  {success: true}     │                     │                     │
     │<─────────────────────│                     │                     │
     │                      │                     │                     │
```

**Request:**
```http
DELETE /api/v1/files/file-uuid-here
Authorization: Bearer <jwt-token>
X-Client-ID: client-uuid (optional)
```

**Response:**
```json
{
  "success": true,
  "message": "File deleted successfully"
}
```

**What Happens:**
1. Validate JWT, extract user_id
2. Verify file belongs to requesting user
3. Delete from appropriate storage
4. Remove encrypted file chunks
5. Update metrics

---

### 7. Enterprise Client Setup Workflow

```
┌──────────┐         ┌─────────────┐         ┌──────────┐
│  Admin   │         │  Wolfronix  │         │    DB    │
└────┬─────┘         └──────┬──────┘         └────┬─────┘
     │                      │                     │
     │  POST /enterprise/   │                     │
     │       register       │                     │
     │  {client_name,       │                     │
     │   api_endpoint,      │                     │
     │   api_key}           │                     │
     │─────────────────────>│                     │
     │                      │                     │
     │                      │  Generate client_id │
     │                      │  (UUID)             │
     │                      │                     │
     │                      │  Generate           │
     │                      │  wolfronix_key      │
     │                      │  (API key for auth) │
     │                      │                     │
     │                      │  INSERT into        │
     │                      │  registered_clients │
     │                      │────────────────────>│
     │                      │                     │
     │  {client_id,         │                     │
     │   wolfronix_key}     │                     │
     │<─────────────────────│                     │
     │                      │                     │
```

**Request:**
```http
POST /api/v1/enterprise/register
Content-Type: application/json

{
  "client_name": "Acme Corp",
  "api_endpoint": "https://api.acme.com",
  "api_key": "acme-secret-api-key"
}
```

**Response:**
```json
{
  "success": true,
  "client_id": "client-uuid-here",
  "wolfronix_key": "wfx_xxxxxxxxxxxx",
  "message": "Enterprise client registered"
}
```

**After Registration:**
- Client includes `X-Client-ID: client-uuid` in all requests
- All user data routes to client's API endpoint
- Wolfronix only stores: client_id, user_count, metrics

---

## Storage Modes

### Self-Hosted Mode (Default)
```
┌─────────────────────────────────────────────────┐
│              WOLFRONIX DATABASE                  │
├─────────────────────────────────────────────────┤
│ users           │ email, password_hash, user_id │
│ secure_storage  │ file metadata, encrypted data │
│ wrapped_keys    │ user encryption keys          │
│ fake_data       │ layer 1 decoys                │
│ metrics         │ encryption/decryption stats   │
└─────────────────────────────────────────────────┘
```

### Enterprise Mode
```
┌─────────────────────────┐      ┌─────────────────────────┐
│   WOLFRONIX DATABASE    │      │    CLIENT DATABASE      │
├─────────────────────────┤      ├─────────────────────────┤
│ registered_clients      │      │ users                   │
│  - client_id            │      │ files (encrypted)       │
│  - api_endpoint         │      │ wrapped_keys            │
│  - user_count           │      │ fake_data               │
│ metrics                 │      │                         │
└─────────────────────────┘      └─────────────────────────┘
        │                                   ▲
        │         API CALLS                 │
        └───────────────────────────────────┘
```

---

## Security Layers

| Layer | Name | Purpose | Technology |
|-------|------|---------|------------|
| **1** | Fake Data Masking | Generates decoy data to confuse attackers | Random data generation |
| **2** | Key Wrapping | Per-user encryption keys wrapped with master key | AES-KW |
| **3** | Encryption | Actual file encryption | AES-256-GCM |
| **4** | Chunked Streaming | Large file handling, parallel processing | 5MB chunks |

---

## Client API Contract (For Enterprise Mode)

Enterprise clients must implement these endpoints:

| Endpoint | Method | Request Body | Response |
|----------|--------|--------------|----------|
| `/wolfronix/files` | POST | `{user_id, file_id, filename, size}` | `{success, file_id}` |
| `/wolfronix/files/upload` | POST | Multipart: metadata + file | `{success, file_id}` |
| `/wolfronix/files/{id}` | GET | - | `{file_id, filename, ...}` |
| `/wolfronix/files/{id}/data` | GET | - | Binary data |
| `/wolfronix/files?user_id={id}` | GET | - | `{files: [...]}` |
| `/wolfronix/files/{id}` | DELETE | - | `{success: true}` |
| `/wolfronix/keys` | POST | `{user_id, wrapped_key}` | `{success: true}` |
| `/wolfronix/keys/{userId}` | GET | - | `{wrapped_key: "..."}` |
| `/wolfronix/dev/files` | POST | `{user_id, fake_data}` | `{success: true}` |

**Authentication:**
- Include `X-Wolfronix-API-Key` header with the key provided during registration

---

## Quick Reference

### Headers Required
| Header | Purpose | When |
|--------|---------|------|
| `Authorization: Bearer <token>` | User authentication | All user endpoints |
| `X-Client-ID: <uuid>` | Enterprise client identifier | Enterprise mode |
| `Content-Type: multipart/form-data` | File upload | Encrypt endpoint |

### Error Responses
```json
{
  "success": false,
  "error": "Error message here"
}
```

### Status Codes
| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request |
| 401 | Unauthorized |
| 403 | Forbidden (not your file) |
| 404 | Not found |
| 500 | Server error |

---

## Client Integration Guide

### Can Wolfronix Work With Any Tech Stack?

**YES! Wolfronix is 100% stack-agnostic.**

Wolfronix is a REST API service. Any programming language or framework that can make HTTPS requests can integrate with Wolfronix.

| Stack | Compatible | How |
|-------|------------|-----|
| **Node.js / Express** | ✅ | fetch, axios, node-fetch |
| **Python / Django / Flask** | ✅ | requests, httpx, aiohttp |
| **Java / Spring** | ✅ | HttpClient, RestTemplate, WebClient |
| **C# / .NET** | ✅ | HttpClient, RestSharp |
| **PHP / Laravel** | ✅ | Guzzle, cURL |
| **Ruby / Rails** | ✅ | Net::HTTP, Faraday, HTTParty |
| **Go** | ✅ | net/http |
| **React / Vue / Angular** | ✅ | fetch, axios |
| **Mobile (iOS/Android)** | ✅ | URLSession, Retrofit, OkHttp |
| **Flutter / Dart** | ✅ | http, dio |

**Why?** Wolfronix exposes standard REST endpoints over HTTPS. No special SDK required.

---

### Can Wolfronix Work With Any Database?

**YES! Wolfronix is 100% database-agnostic.**

In **Enterprise Mode**, Wolfronix never touches your database directly. It calls YOUR API endpoints, and YOU decide how to store the data.

| Database | Compatible | Notes |
|----------|------------|-------|
| **PostgreSQL** | ✅ | Any version |
| **MySQL / MariaDB** | ✅ | Any version |
| **MongoDB** | ✅ | NoSQL works perfectly |
| **SQL Server** | ✅ | Any version |
| **Oracle** | ✅ | Any version |
| **SQLite** | ✅ | For lightweight apps |
| **Redis** | ✅ | For caching/sessions |
| **DynamoDB** | ✅ | AWS native |
| **Firestore** | ✅ | Firebase/GCP |
| **Cassandra** | ✅ | Distributed systems |
| **CockroachDB** | ✅ | Distributed SQL |

**Why?** Wolfronix sends encrypted data to YOUR API. Your API stores it however you want.

```
Wolfronix → Your API → Your Database (any type)
```

---

## Step-by-Step Client Integration

### Step 1: Get Your Subscription

Contact Wolfronix sales to get:
- `client_id` - Your unique identifier
- `wolfronix_key` - API key for authentication
- `wolfronix_endpoint` - Base URL (e.g., `https://wolfronix.yourcompany.com`)

### Step 2: Implement Required API Endpoints (Enterprise Mode)

Your backend must implement these endpoints for Wolfronix to store/retrieve encrypted data:

```
YOUR_API_BASE_URL/
├── POST   /wolfronix/files          # Store file metadata
├── POST   /wolfronix/files/upload   # Store file + data (multipart)
├── GET    /wolfronix/files/{id}     # Get file metadata
├── GET    /wolfronix/files/{id}/data # Get encrypted file bytes
├── GET    /wolfronix/files?user_id={id} # List user's files
├── DELETE /wolfronix/files/{id}     # Delete file
├── POST   /wolfronix/keys           # Store user's wrapped key
├── GET    /wolfronix/keys/{userId}  # Get user's wrapped key
└── POST   /wolfronix/dev/files      # Store fake decoy data
```

### Step 3: Register Your API with Wolfronix

```bash
curl -X POST https://wolfronix-server/api/v1/enterprise/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Your Company Name",
    "api_endpoint": "https://your-api.com",
    "api_key": "your-api-secret-key"
  }'
```

Response:
```json
{
  "client_id": "your-client-uuid",
  "wolfronix_key": "wfx_xxxxxxxxxxxxx"
}
```

### Step 4: Integrate Into Your Application

---

## Code Examples By Stack

### JavaScript / Node.js

```javascript
// wolfronix.js - Wolfronix Client SDK
class WolfronixClient {
  constructor(baseUrl, clientId) {
    this.baseUrl = baseUrl;
    this.clientId = clientId;
    this.token = null;
  }

  async register(email, password) {
    const response = await fetch(`${this.baseUrl}/api/v1/keys/register`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-Client-ID': this.clientId
      },
      body: JSON.stringify({ email, password })
    });
    const data = await response.json();
    this.token = data.token;
    return data;
  }

  async login(email, password) {
    const response = await fetch(`${this.baseUrl}/api/v1/keys/login`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-Client-ID': this.clientId
      },
      body: JSON.stringify({ email, password })
    });
    const data = await response.json();
    this.token = data.token;
    return data;
  }

  async encryptFile(file, userId) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('user_id', userId);

    const response = await fetch(`${this.baseUrl}/api/v1/encrypt`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'X-Client-ID': this.clientId
      },
      body: formData
    });
    return response.json();
  }

  async decryptFile(fileId) {
    const response = await fetch(`${this.baseUrl}/api/v1/decrypt/${fileId}`, {
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'X-Client-ID': this.clientId
      }
    });
    return response.blob();
  }

  async listFiles() {
    const response = await fetch(`${this.baseUrl}/api/v1/files`, {
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'X-Client-ID': this.clientId
      }
    });
    return response.json();
  }

  async deleteFile(fileId) {
    const response = await fetch(`${this.baseUrl}/api/v1/files/${fileId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'X-Client-ID': this.clientId
      }
    });
    return response.json();
  }
}

// Usage
const wolfronix = new WolfronixClient('https://wolfronix-server:5002', 'your-client-id');
await wolfronix.login('user@example.com', 'password123');
const result = await wolfronix.encryptFile(fileBlob, 'user-uuid');
console.log('Encrypted file ID:', result.file_id);
```

---

### Python

```python
# wolfronix.py - Wolfronix Client SDK
import requests

class WolfronixClient:
    def __init__(self, base_url, client_id):
        self.base_url = base_url
        self.client_id = client_id
        self.token = None
    
    def _headers(self, include_auth=True):
        headers = {'X-Client-ID': self.client_id}
        if include_auth and self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers
    
    def register(self, email, password):
        response = requests.post(
            f'{self.base_url}/api/v1/keys/register',
            json={'email': email, 'password': password},
            headers=self._headers(include_auth=False),
            verify=False  # For self-signed certs
        )
        data = response.json()
        self.token = data.get('token')
        return data
    
    def login(self, email, password):
        response = requests.post(
            f'{self.base_url}/api/v1/keys/login',
            json={'email': email, 'password': password},
            headers=self._headers(include_auth=False),
            verify=False
        )
        data = response.json()
        self.token = data.get('token')
        return data
    
    def encrypt_file(self, file_path, user_id):
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {'user_id': user_id}
            response = requests.post(
                f'{self.base_url}/api/v1/encrypt',
                files=files,
                data=data,
                headers=self._headers(),
                verify=False
            )
        return response.json()
    
    def decrypt_file(self, file_id):
        response = requests.get(
            f'{self.base_url}/api/v1/decrypt/{file_id}',
            headers=self._headers(),
            verify=False
        )
        return response.content
    
    def list_files(self):
        response = requests.get(
            f'{self.base_url}/api/v1/files',
            headers=self._headers(),
            verify=False
        )
        return response.json()
    
    def delete_file(self, file_id):
        response = requests.delete(
            f'{self.base_url}/api/v1/files/{file_id}',
            headers=self._headers(),
            verify=False
        )
        return response.json()


# Usage
client = WolfronixClient('https://localhost:5002', 'your-client-id')
client.login('user@example.com', 'password123')
result = client.encrypt_file('/path/to/document.pdf', 'user-uuid')
print(f"Encrypted file ID: {result['file_id']}")
```

---

### Java / Spring

```java
// WolfronixClient.java
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.core.io.FileSystemResource;

public class WolfronixClient {
    private final String baseUrl;
    private final String clientId;
    private String token;
    private final RestTemplate restTemplate;

    public WolfronixClient(String baseUrl, String clientId) {
        this.baseUrl = baseUrl;
        this.clientId = clientId;
        this.restTemplate = new RestTemplate();
    }

    public Map<String, Object> login(String email, String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Client-ID", clientId);

        Map<String, String> body = Map.of("email", email, "password", password);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
            baseUrl + "/api/v1/keys/login", request, Map.class
        );
        
        this.token = (String) response.getBody().get("token");
        return response.getBody();
    }

    public Map<String, Object> encryptFile(File file, String userId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", "Bearer " + token);
        headers.set("X-Client-ID", clientId);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new FileSystemResource(file));
        body.add("user_id", userId);

        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
            baseUrl + "/api/v1/encrypt", request, Map.class
        );
        return response.getBody();
    }

    public byte[] decryptFile(String fileId) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);
        headers.set("X-Client-ID", clientId);

        HttpEntity<?> request = new HttpEntity<>(headers);

        ResponseEntity<byte[]> response = restTemplate.exchange(
            baseUrl + "/api/v1/decrypt/" + fileId,
            HttpMethod.GET, request, byte[].class
        );
        return response.getBody();
    }
}

// Usage
WolfronixClient client = new WolfronixClient("https://localhost:5002", "your-client-id");
client.login("user@example.com", "password123");
Map<String, Object> result = client.encryptFile(new File("/path/to/doc.pdf"), "user-uuid");
System.out.println("Encrypted file ID: " + result.get("file_id"));
```

---

### PHP / Laravel

```php
<?php
// WolfronixClient.php

class WolfronixClient {
    private $baseUrl;
    private $clientId;
    private $token;

    public function __construct($baseUrl, $clientId) {
        $this->baseUrl = $baseUrl;
        $this->clientId = $clientId;
    }

    public function login($email, $password) {
        $response = Http::withHeaders([
            'X-Client-ID' => $this->clientId
        ])->withoutVerifying()->post("{$this->baseUrl}/api/v1/keys/login", [
            'email' => $email,
            'password' => $password
        ]);

        $data = $response->json();
        $this->token = $data['token'] ?? null;
        return $data;
    }

    public function encryptFile($filePath, $userId) {
        $response = Http::withHeaders([
            'Authorization' => "Bearer {$this->token}",
            'X-Client-ID' => $this->clientId
        ])->withoutVerifying()->attach(
            'file', file_get_contents($filePath), basename($filePath)
        )->post("{$this->baseUrl}/api/v1/encrypt", [
            'user_id' => $userId
        ]);

        return $response->json();
    }

    public function decryptFile($fileId) {
        $response = Http::withHeaders([
            'Authorization' => "Bearer {$this->token}",
            'X-Client-ID' => $this->clientId
        ])->withoutVerifying()->get("{$this->baseUrl}/api/v1/decrypt/{$fileId}");

        return $response->body();
    }

    public function listFiles() {
        $response = Http::withHeaders([
            'Authorization' => "Bearer {$this->token}",
            'X-Client-ID' => $this->clientId
        ])->withoutVerifying()->get("{$this->baseUrl}/api/v1/files");

        return $response->json();
    }
}

// Usage
$client = new WolfronixClient('https://localhost:5002', 'your-client-id');
$client->login('user@example.com', 'password123');
$result = $client->encryptFile('/path/to/document.pdf', 'user-uuid');
echo "Encrypted file ID: " . $result['file_id'];
```

---

### C# / .NET

```csharp
// WolfronixClient.cs
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

public class WolfronixClient
{
    private readonly HttpClient _client;
    private readonly string _baseUrl;
    private readonly string _clientId;
    private string _token;

    public WolfronixClient(string baseUrl, string clientId)
    {
        _baseUrl = baseUrl;
        _clientId = clientId;
        
        var handler = new HttpClientHandler {
            ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
        };
        _client = new HttpClient(handler);
        _client.DefaultRequestHeaders.Add("X-Client-ID", clientId);
    }

    public async Task<Dictionary<string, object>> LoginAsync(string email, string password)
    {
        var content = new StringContent(
            JsonSerializer.Serialize(new { email, password }),
            System.Text.Encoding.UTF8,
            "application/json"
        );

        var response = await _client.PostAsync($"{_baseUrl}/api/v1/keys/login", content);
        var json = await response.Content.ReadAsStringAsync();
        var data = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
        
        _token = data["token"].ToString();
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", _token);
        
        return data;
    }

    public async Task<Dictionary<string, object>> EncryptFileAsync(string filePath, string userId)
    {
        using var form = new MultipartFormDataContent();
        using var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
        
        form.Add(fileContent, "file", Path.GetFileName(filePath));
        form.Add(new StringContent(userId), "user_id");

        var response = await _client.PostAsync($"{_baseUrl}/api/v1/encrypt", form);
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<Dictionary<string, object>>(json);
    }

    public async Task<byte[]> DecryptFileAsync(string fileId)
    {
        return await _client.GetByteArrayAsync($"{_baseUrl}/api/v1/decrypt/{fileId}");
    }
}

// Usage
var client = new WolfronixClient("https://localhost:5002", "your-client-id");
await client.LoginAsync("user@example.com", "password123");
var result = await client.EncryptFileAsync(@"C:\path\to\document.pdf", "user-uuid");
Console.WriteLine($"Encrypted file ID: {result["file_id"]}");
```

---

### cURL Examples (For Testing)

```bash
# Register
curl -k -X POST https://localhost:5002/api/v1/keys/register \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: your-client-id" \
  -d '{"email":"user@example.com","password":"password123"}'

# Login
curl -k -X POST https://localhost:5002/api/v1/keys/login \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: your-client-id" \
  -d '{"email":"user@example.com","password":"password123"}'

# Encrypt File
curl -k -X POST https://localhost:5002/api/v1/encrypt \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "X-Client-ID: your-client-id" \
  -F "file=@/path/to/document.pdf" \
  -F "user_id=user-uuid"

# Decrypt File
curl -k -X GET https://localhost:5002/api/v1/decrypt/FILE_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "X-Client-ID: your-client-id" \
  --output decrypted_file.pdf

# List Files
curl -k -X GET https://localhost:5002/api/v1/files \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "X-Client-ID: your-client-id"

# Delete File
curl -k -X DELETE https://localhost:5002/api/v1/files/FILE_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "X-Client-ID: your-client-id"
```

---

## Implementing Your Storage API (Enterprise Mode)

When Wolfronix calls your API, here's what to implement:

### Example: Node.js/Express Backend

```javascript
// routes/wolfronix.js
const express = require('express');
const router = express.Router();
const db = require('../database'); // Your database connection

// Middleware to verify Wolfronix API key
const verifyWolfronixKey = (req, res, next) => {
  const apiKey = req.headers['x-wolfronix-api-key'];
  if (apiKey !== process.env.WOLFRONIX_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
};

router.use(verifyWolfronixKey);

// Store file metadata
router.post('/files', async (req, res) => {
  const { user_id, file_id, filename, size } = req.body;
  await db.query(
    'INSERT INTO encrypted_files (file_id, user_id, filename, size) VALUES (?, ?, ?, ?)',
    [file_id, user_id, filename, size]
  );
  res.json({ success: true, file_id });
});

// Store file with data (multipart)
router.post('/files/upload', upload.single('file'), async (req, res) => {
  const { user_id, file_id, filename } = req.body;
  const encryptedData = req.file.buffer;
  
  await db.query(
    'INSERT INTO encrypted_files (file_id, user_id, filename, data, size) VALUES (?, ?, ?, ?, ?)',
    [file_id, user_id, filename, encryptedData, encryptedData.length]
  );
  res.json({ success: true, file_id });
});

// Get file metadata
router.get('/files/:id', async (req, res) => {
  const [rows] = await db.query(
    'SELECT file_id, user_id, filename, size, created_at FROM encrypted_files WHERE file_id = ?',
    [req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
});

// Get encrypted file data
router.get('/files/:id/data', async (req, res) => {
  const [rows] = await db.query(
    'SELECT data FROM encrypted_files WHERE file_id = ?',
    [req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
  res.send(rows[0].data);
});

// List user's files
router.get('/files', async (req, res) => {
  const userId = req.query.user_id;
  const [rows] = await db.query(
    'SELECT file_id, filename, size, created_at FROM encrypted_files WHERE user_id = ?',
    [userId]
  );
  res.json({ files: rows });
});

// Delete file
router.delete('/files/:id', async (req, res) => {
  await db.query('DELETE FROM encrypted_files WHERE file_id = ?', [req.params.id]);
  res.json({ success: true });
});

// Store wrapped key
router.post('/keys', async (req, res) => {
  const { user_id, wrapped_key } = req.body;
  await db.query(
    'INSERT INTO user_keys (user_id, wrapped_key) VALUES (?, ?) ON DUPLICATE KEY UPDATE wrapped_key = ?',
    [user_id, wrapped_key, wrapped_key]
  );
  res.json({ success: true });
});

// Get wrapped key
router.get('/keys/:userId', async (req, res) => {
  const [rows] = await db.query(
    'SELECT wrapped_key FROM user_keys WHERE user_id = ?',
    [req.params.userId]
  );
  if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ wrapped_key: rows[0].wrapped_key });
});

// Store fake/decoy data
router.post('/dev/files', async (req, res) => {
  const { user_id, fake_data } = req.body;
  await db.query(
    'INSERT INTO decoy_data (user_id, data) VALUES (?, ?)',
    [user_id, fake_data]
  );
  res.json({ success: true });
});

module.exports = router;
```

### Database Schema (Example for MySQL/PostgreSQL)

```sql
-- Encrypted files storage
CREATE TABLE encrypted_files (
    id SERIAL PRIMARY KEY,
    file_id VARCHAR(36) UNIQUE NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    data BYTEA,  -- or LONGBLOB for MySQL
    size BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_files_user ON encrypted_files(user_id);

-- User encryption keys
CREATE TABLE user_keys (
    user_id VARCHAR(36) PRIMARY KEY,
    wrapped_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Decoy data (Layer 1)
CREATE TABLE decoy_data (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## FAQ

### Q: Do I need to expose my database to Wolfronix?
**A: NO.** Wolfronix calls your API endpoints. Your API talks to your database. Wolfronix never sees your database.

### Q: What if my app uses GraphQL instead of REST?
**A:** Create REST endpoints specifically for Wolfronix storage. Your main app can still use GraphQL.

### Q: Can I use file storage (S3, Azure Blob) instead of database?
**A:** Yes! In your `/files/upload` and `/files/:id/data` endpoints, store/retrieve from S3 or any blob storage.

### Q: What data does Wolfronix store about my users?
**A:** In Enterprise Mode, Wolfronix only stores:
- Your client_id
- Total user count (for billing)
- Encryption/decryption metrics
- **NO user data, files, or keys**

### Q: Is the connection secure?
**A:** Yes. All communication uses HTTPS (TLS 1.2+). Self-signed certs for development, trusted CA certs for production.

### Q: What happens if Wolfronix goes down?
**A:** Your encrypted data remains safe in YOUR database. You just can't decrypt until Wolfronix is back. Consider keeping backups of critical keys.

### Q: Can I self-host Wolfronix?
**A:** Yes! Wolfronix can be deployed on your own infrastructure using Docker.
