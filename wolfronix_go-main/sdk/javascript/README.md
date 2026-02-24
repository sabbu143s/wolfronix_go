# wolfronix-sdk

Official JavaScript/TypeScript SDK for **Wolfronix** — Zero-knowledge encryption made simple.

[![npm version](https://badge.fury.io/js/wolfronix-sdk.svg)](https://www.npmjs.com/package/wolfronix-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔐 **Zero-Knowledge Encryption** — Keys generated client-side, never leave your device
- 🏢 **Enterprise Ready** — Seamless integration with your existing storage (Supabase, MongoDB, MySQL, Firebase, PostgreSQL)
- 🚀 **Simple API** — Encrypt files in 2 lines of code
- 📦 **TypeScript Native** — Full type definitions included
- 🌐 **Universal** — Works in Node.js 18+ and modern browsers
- 🔄 **Auto Retry** — Built-in retry logic with exponential backoff
- 💬 **E2E Chat** — Hybrid RSA+AES message encryption out of the box
- 📡 **Real-Time Streaming** — WebSocket-based streaming encryption/decryption

---

## Installation

### npm / yarn / pnpm

```bash
npm install wolfronix-sdk
```

### Browser (Script Tag)

For plain HTML/JS apps, use the pre-built browser bundle:

```html
<script src="https://unpkg.com/wolfronix-sdk/dist/index.global.js"></script>
<script>
  // All exports are available on the global `Wolfronix` object
  const wfx = new Wolfronix.default({
    baseUrl: 'https://your-server:9443',
    clientId: 'your-client-id',
    wolfronixKey: 'your-api-key'
  });
</script>
```

Or host the bundle yourself — copy `node_modules/wolfronix-sdk/dist/index.global.js` to your project.

---

## Quick Start

### 1. Connect to Wolfronix Server

```javascript
import Wolfronix from 'wolfronix-sdk';

const wfx = new Wolfronix({
  baseUrl: 'https://your-wolfronix-server:9443',
  clientId: 'your-client-id',        // From enterprise registration
  wolfronixKey: 'your-api-key',       // From enterprise registration
});
```

### 2. Register a User (First Time Only)

```javascript
await wfx.register('user@example.com', 'securePassword');
// Generates RSA key pair client-side, wraps private key with password,
// sends only the ENCRYPTED key to the server (zero-knowledge)
```

### 3. Login (Subsequent Visits)

```javascript
await wfx.login('user@example.com', 'securePassword');
// Fetches encrypted private key from server, decrypts it locally
```

### 4. Encrypt a File

```javascript
const result = await wfx.encrypt(file); // File or Blob
console.log('Encrypted! File ID:', result.file_id);
console.log('Time:', result.enc_time_ms, 'ms');
```

### 5. Decrypt a File

```javascript
const blob = await wfx.decrypt(result.file_id);
// blob is a standard Blob — display, download, or process it
```

### 6. List & Delete Files

```javascript
const { files } = await wfx.listFiles();
await wfx.deleteFile(files[0].file_id);
```

---

## Step-by-Step Integration Guide

### Plain HTML/JS Web App

```html
<!DOCTYPE html>
<html>
<head>
  <title>My Secure App</title>
  <script src="https://unpkg.com/wolfronix-sdk/dist/index.global.js"></script>
</head>
<body>
  <input type="email" id="email" placeholder="Email">
  <input type="password" id="password" placeholder="Password">
  <button onclick="doLogin()">Login</button>
  <button onclick="doRegister()">Register</button>

  <hr>

  <input type="file" id="fileInput">
  <button onclick="doEncrypt()">Encrypt & Upload</button>
  <button onclick="doList()">List Files</button>

  <div id="output"></div>

  <script>
    const wfx = new Wolfronix.default({
      baseUrl: 'https://your-server:9443',
      clientId: 'your-client-id',
      wolfronixKey: 'your-api-key'
    });

    async function doRegister() {
      const email = document.getElementById('email').value;
      const pass = document.getElementById('password').value;
      await wfx.register(email, pass);
      alert('Registered! Keys generated.');
    }

    async function doLogin() {
      const email = document.getElementById('email').value;
      const pass = document.getElementById('password').value;
      await wfx.login(email, pass);
      alert('Logged in! User: ' + wfx.getUserId());
    }

    async function doEncrypt() {
      const file = document.getElementById('fileInput').files[0];
      const result = await wfx.encrypt(file);
      document.getElementById('output').textContent =
        'Encrypted! ID: ' + result.file_id + ' (' + result.enc_time_ms + 'ms)';
    }

    async function doList() {
      const { files } = await wfx.listFiles();
      document.getElementById('output').textContent =
        files.map(f => f.original_name + ' (ID: ' + f.file_id + ')').join('\n');
    }
  </script>
</body>
</html>
```

### React / Next.js

```typescript
import Wolfronix from 'wolfronix-sdk';

// Create a singleton instance (e.g., in a context or module)
const wfx = new Wolfronix({
  baseUrl: process.env.NEXT_PUBLIC_WOLFRONIX_URL!,
  clientId: process.env.NEXT_PUBLIC_WOLFRONIX_CLIENT_ID!,
  wolfronixKey: process.env.NEXT_PUBLIC_WOLFRONIX_KEY!,
});

export default function FileVault() {
  const [files, setFiles] = useState([]);

  const handleLogin = async (email: string, password: string) => {
    await wfx.login(email, password);
    const { files } = await wfx.listFiles();
    setFiles(files);
  };

  const handleUpload = async (file: File) => {
    const result = await wfx.encrypt(file);
    console.log('Encrypted:', result.file_id);
    // Refresh file list
    const { files } = await wfx.listFiles();
    setFiles(files);
  };

  const handleDownload = async (fileId: string, filename: string) => {
    const blob = await wfx.decrypt(fileId);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <input type="file" onChange={(e) => handleUpload(e.target.files![0])} />
      {files.map(f => (
        <div key={f.file_id}>
          {f.original_name}
          <button onClick={() => handleDownload(f.file_id, f.original_name)}>
            Download
          </button>
        </div>
      ))}
    </div>
  );
}
```

### React Hook

```typescript
// hooks/useWolfronix.ts
import { useState, useCallback, useMemo } from 'react';
import Wolfronix, { FileInfo } from 'wolfronix-sdk';

export function useWolfronix(baseUrl: string, clientId?: string, wolfronixKey?: string) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [files, setFiles] = useState<FileInfo[]>([]);

  const client = useMemo(
    () => new Wolfronix({ baseUrl, clientId, wolfronixKey }),
    [baseUrl, clientId, wolfronixKey]
  );

  const login = useCallback(async (email: string, password: string) => {
    setIsLoading(true);
    try {
      return await client.login(email, password);
    } catch (e) {
      setError(e as Error);
      throw e;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  const encrypt = useCallback(async (file: File) => {
    setIsLoading(true);
    try {
      const result = await client.encrypt(file);
      const { files } = await client.listFiles();
      setFiles(files);
      return result;
    } catch (e) {
      setError(e as Error);
      throw e;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  const decrypt = useCallback(async (fileId: string) => {
    setIsLoading(true);
    try {
      return await client.decrypt(fileId);
    } catch (e) {
      setError(e as Error);
      throw e;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  return { client, isLoading, error, files, login, encrypt, decrypt };
}
```

### Node.js (Server-Side)

```typescript
import Wolfronix from 'wolfronix-sdk';
import * as fs from 'fs';

const wfx = new Wolfronix({
  baseUrl: 'https://wolfronix-server:9443',
  clientId: 'your-client-id',
  wolfronixKey: 'your-api-key',
  insecure: true  // For self-signed certs in development
});

async function main() {
  await wfx.login('user@example.com', 'password123');

  // Encrypt a file
  const fileBuffer = fs.readFileSync('document.pdf');
  const { file_id } = await wfx.encrypt(fileBuffer, 'document.pdf');
  console.log('Encrypted file ID:', file_id);

  // List all files
  const { files } = await wfx.listFiles();
  console.log('Your files:', files);

  // Decrypt and save
  const decrypted = await wfx.decryptToBuffer(file_id);
  fs.writeFileSync('decrypted.pdf', Buffer.from(decrypted));
}

main();
```

---

## API Reference

### Constructor

```typescript
new Wolfronix(config: WolfronixConfig | string)
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | `string` | **required** | Wolfronix server URL |
| `clientId` | `string` | `''` | Enterprise client ID |
| `wolfronixKey` | `string` | `''` | API key (sent as `X-Wolfronix-Key` header) |
| `timeout` | `number` | `30000` | Request timeout in ms (file uploads bypass this) |
| `retries` | `number` | `3` | Max retry attempts with exponential backoff |
| `insecure` | `boolean` | `false` | Skip SSL verification (Node.js only) |

You can also pass just a URL string: `new Wolfronix('https://server:9443')`

---

### Authentication

| Method | Returns | Description |
|--------|---------|-------------|
| `register(email, password)` | `Promise<AuthResponse>` | Generate RSA keys + register (first time) |
| `login(email, password)` | `Promise<AuthResponse>` | Fetch & unwrap keys (subsequent logins) |
| `setToken(token, userId?)` | `void` | Set auth token directly (for custom auth) |
| `logout()` | `void` | Clear keys and session from memory |
| `isAuthenticated()` | `boolean` | Check if user is logged in |
| `getUserId()` | `string \| null` | Get current user ID |
| `hasPrivateKey()` | `boolean` | Check if RSA private key is loaded in memory |

---

### File Operations

| Method | Returns | Description |
|--------|---------|-------------|
| `encrypt(file, filename?)` | `Promise<EncryptResponse>` | Encrypt and store a file |
| `decrypt(fileId, role?)` | `Promise<Blob>` | Decrypt file → Blob (for browser display/download) |
| `decryptToBuffer(fileId, role?)` | `Promise<ArrayBuffer>` | Decrypt file → ArrayBuffer (for Node.js) |
| `getFileKey(fileId)` | `Promise<KeyPartResponse>` | Get encrypted key_part_a (advanced use) |
| `listFiles()` | `Promise<ListFilesResponse>` | List user's encrypted files |
| `deleteFile(fileId)` | `Promise<DeleteResponse>` | Delete an encrypted file |

**`EncryptResponse` fields:**
```typescript
{
  status: string;
  file_id: string;
  file_size: number;
  enc_time_ms: number;
  // Detailed timing breakdown:
  upload_ms?: number;    // Network upload time
  read_ms?: number;      // Server file read time
  encrypt_ms?: number;   // AES-256-GCM encryption time
  store_ms?: number;     // Storage write time
}
```

---

### E2E Chat Encryption

Turn any chat app into a secure, end-to-end encrypted messenger.

| Method | Returns | Description |
|--------|---------|-------------|
| `getPublicKey(userId, clientId?)` | `Promise<CryptoKey>` | Fetch a user's RSA public key |
| `encryptMessage(text, recipientId)` | `Promise<string>` | Encrypt text for a recipient (returns JSON packet) |
| `decryptMessage(packetString)` | `Promise<string>` | Decrypt a received message packet |

**Sender (Alice):**
```typescript
const securePacket = await wfx.encryptMessage("Secret meeting at 5 PM", "bob_user_id");

// Send via your regular chat backend (Socket.io, Firebase, etc.)
chatSocket.emit('message', { to: 'bob', text: securePacket });
```

**Recipient (Bob):**
```typescript
chatSocket.on('message', async (msg) => {
  const plainText = await wfx.decryptMessage(msg.text);
  console.log("Decrypted:", plainText);
});
```

---

### Server-Side Message Encryption

For messages that need **server-managed** encryption (Layer 3/4 dual-key split):

| Method | Returns | Description |
|--------|---------|-------------|
| `serverEncrypt(message, options?)` | `Promise<ServerEncryptResult>` | Encrypt a message server-side |
| `serverDecrypt(params)` | `Promise<string>` | Decrypt a server-encrypted message |
| `serverEncryptBatch(messages, options?)` | `Promise<ServerBatchEncryptResult>` | Batch encrypt multiple messages |
| `serverDecryptBatchItem(item)` | `Promise<string>` | Decrypt a single batch item |

```typescript
// Encrypt
const encrypted = await wfx.serverEncrypt("Confidential data", { layer: 4 });

// Decrypt
const original = await wfx.serverDecrypt({
  encryptedMessage: encrypted.encrypted_message,
  nonce: encrypted.nonce,
  keyPartA: encrypted.key_part_a,
  messageTag: encrypted.message_tag
});

// Batch encrypt
const batch = await wfx.serverEncryptBatch([
  { id: 'msg1', message: 'Hello' },
  { id: 'msg2', message: 'World' }
], { layer: 4 });
```

---

### Real-Time Streaming Encryption

For encrypting/decrypting live data streams (audio, video, real-time feeds) via WebSocket:

| Method | Returns | Description |
|--------|---------|-------------|
| `createStream(direction, streamKey?)` | `Promise<WolfronixStream>` | Open a streaming encryption session |

```typescript
// Encrypt stream
const stream = await wfx.createStream('encrypt');
stream.onData((chunk, seq) => sendToRecipient(chunk));
stream.onError((err) => console.error(err));

const processed = await stream.send('data to encrypt');       // Text
const processed2 = await stream.sendBinary(audioChunk);       // Binary

// Save these for the recipient to decrypt:
console.log('Key:', stream.keyPartA, 'Tag:', stream.streamTag);

const summary = await stream.end();
console.log('Chunks processed:', summary.chunksProcessed);

// Decrypt stream (recipient)
const decStream = await wfx.createStream('decrypt', {
  keyPartA: senderKeyPartA,
  streamTag: senderStreamTag
});
decStream.onData((chunk, seq) => playAudio(chunk));
```

---

### Admin API (Enterprise Client Management)

For managing enterprise clients programmatically:

```typescript
import { WolfronixAdmin } from 'wolfronix-sdk';

const admin = new WolfronixAdmin({
  baseUrl: 'https://your-server:9443',
  adminKey: 'your-admin-api-key'
});
```

| Method | Returns | Description |
|--------|---------|-------------|
| `registerClient(params)` | `Promise<RegisterClientResponse>` | Register a new enterprise client |
| `listClients()` | `Promise<ListClientsResponse>` | List all registered clients |
| `getClient(clientId)` | `Promise<EnterpriseClient>` | Get details for a specific client |
| `updateClient(clientId, params)` | `Promise<UpdateClientResponse>` | Update client configuration |
| `deactivateClient(clientId)` | `Promise<DeactivateClientResponse>` | Deactivate (revoke) a client |
| `healthCheck()` | `Promise<boolean>` | Check server health |

```typescript
// Register a new client with Supabase connector
const result = await admin.registerClient({
  client_id: 'acme_corp',
  client_name: 'Acme Corporation',
  db_type: 'supabase',           // or: mongodb, mysql, firebase, postgresql, custom_api
  db_config: JSON.stringify({
    supabase_url: 'https://xxx.supabase.co',
    supabase_service_key: 'eyJ...'
  })
});

console.log('Wolfronix Key:', result.wolfronix_key); // Give this to the client
```

---

### Utility Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `getMetrics()` | `Promise<MetricsResponse>` | Get encryption/decryption stats |
| `healthCheck()` | `Promise<boolean>` | Check if server is reachable |

---

## Error Handling

The SDK provides typed error classes for different failure scenarios:

```typescript
import Wolfronix, {
  WolfronixError,        // Base error class
  AuthenticationError,   // Invalid credentials or expired session
  FileNotFoundError,     // File doesn't exist
  PermissionDeniedError, // Not authorized for this file
  NetworkError,          // Server unreachable
  ValidationError        // Invalid input parameters
} from 'wolfronix-sdk';

try {
  await wfx.encrypt(file);
} catch (error) {
  if (error instanceof AuthenticationError) {
    // Redirect to login
  } else if (error instanceof FileNotFoundError) {
    // File was deleted
  } else if (error instanceof NetworkError) {
    // Server down — SDK already retried 3 times
  } else if (error instanceof ValidationError) {
    // Bad input (e.g., missing file, empty message)
  }
}
```

All errors include:
- `error.message` — Human-readable description
- `error.code` — Machine-readable error code
- `error.statusCode` — HTTP status code (if applicable)
- `error.details` — Server error details (if available)

---

## Security Architecture

### How It Works

```
                    Your App                          Wolfronix Engine
                ┌──────────────┐              ┌────────────────────────┐
  User ──────▶  │  SDK (Browser)│ ──────────▶  │  AES-256-GCM Encrypt  │
  Password      │              │   HTTPS       │  RSA Dual-Key Split   │
                │  RSA Keys    │              │  RBAC Masking          │
                │  (client-    │  ◀──────────  │                        │
                │   side only) │   Encrypted   │  Stores NOTHING       │
                └──────────────┘   Blob Only   │  decryptable alone    │
                                               └────────────────────────┘
                                                          │
                                                          ▼
                                               ┌────────────────────────┐
                                               │  Your Database          │
                                               │  (Supabase, MongoDB,   │
                                               │   PostgreSQL, etc.)    │
                                               │  Stores encrypted      │
                                               │  blobs only            │
                                               └────────────────────────┘
```

### Key Security Properties

| Property | Implementation |
|----------|---------------|
| **Encryption** | AES-256-GCM (authenticated, tamper-proof) |
| **Key Transport** | RSA-OAEP with SHA-256 |
| **Key Wrapping** | PBKDF2 (100,000 iterations) + AES-GCM |
| **Dual-Key Split** | AES key split in half; each half encrypted with different RSA key |
| **Zero-Knowledge** | Private keys wrapped client-side; server never sees raw keys |
| **Auth** | API key (`X-Wolfronix-Key`) + zero-knowledge login |

### Zero-Knowledge Decryption Flow

```
Client                              Wolfronix Server
  │                                       │
  │  GET /files/{id}/key                  │
  │──────────────────────────────────────►│
  │  { key_part_a: "<RSA-OAEP encrypted>"}│
  │◄──────────────────────────────────────│
  │                                       │
  │  [Decrypt key_part_a locally          │
  │   with private key (RSA-OAEP)]        │
  │                                       │
  │  POST /files/{id}/decrypt             │
  │  { decrypted_key_a: "<base64>" }      │
  │──────────────────────────────────────►│
  │                                       │
  │  [Server combines key_a + key_b,      │
  │   decrypts with AES-256-GCM]          │
  │                                       │
  │  <decrypted file bytes>               │
  │◄──────────────────────────────────────│
```

---

## TypeScript Types

All interfaces are exported for full type safety:

```typescript
import Wolfronix, {
  // Config
  WolfronixConfig,
  WolfronixAdminConfig,

  // Responses
  AuthResponse,
  EncryptResponse,
  FileInfo,
  ListFilesResponse,
  DeleteResponse,
  KeyPartResponse,
  MetricsResponse,

  // Message Encryption
  EncryptMessagePacket,
  ServerEncryptResult,
  ServerDecryptParams,
  ServerBatchEncryptResult,

  // Streaming
  WolfronixStream,
  StreamSession,
  StreamChunk,

  // Enterprise Admin
  WolfronixAdmin,
  RegisterClientRequest,
  RegisterClientResponse,
  EnterpriseClient,
  ListClientsResponse,
  UpdateClientRequest,
  UpdateClientResponse,
  DeactivateClientResponse,

  // Error Classes
  WolfronixError,
  AuthenticationError,
  FileNotFoundError,
  PermissionDeniedError,
  NetworkError,
  ValidationError
} from 'wolfronix-sdk';
```

---

## Real-World Use Cases

| Industry | Application | How Wolfronix Helps |
|----------|------------|---------------------|
| 🏥 **Healthcare** | Patient records, lab reports | HIPAA-compliant encryption at rest |
| 🏦 **Finance** | Invoices, tax docs, receipts | End-to-end encrypted banking documents |
| ⚖️ **Legal** | Contracts, case files | Zero-knowledge confidential storage |
| ☁️ **Cloud Storage** | Drive/Dropbox alternatives | Encrypted file vault with user-owned keys |
| 🏢 **Enterprise** | HR records, internal docs | Per-employee encryption isolation |
| 💬 **Messaging** | Chat attachments | Encrypted file sharing + E2E messages |
| 🎓 **Education** | Exam papers, student data | Tamper-proof academic records |

---

## Backend Integration

Your backend only needs to store/retrieve encrypted blobs. Wolfronix handles all crypto.

### Supported Connectors (Managed)

| Connector | `db_type` | What You Provide |
|-----------|-----------|-----------------|
| Supabase | `supabase` | `supabase_url`, `supabase_service_key` |
| MongoDB | `mongodb` | `connection_string`, `database` |
| MySQL | `mysql` | `host`, `port`, `user`, `password`, `database` |
| Firebase | `firebase` | `project_id`, `service_account_key` |
| PostgreSQL | `postgresql` | `host`, `port`, `user`, `password`, `database` |
| Custom API | `custom_api` | Your own REST endpoint |

### Custom API Mode

If using `custom_api`, your backend must implement these endpoints:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/wolfronix/files/upload` | Store encrypted file + metadata |
| `GET` | `/wolfronix/files/{id}` | Retrieve file metadata |
| `GET` | `/wolfronix/files/{id}/data` | Retrieve encrypted blob |
| `DELETE` | `/wolfronix/files/{id}` | Delete file |

---

## Requirements

- **Node.js:** 18+ (for server-side usage)
- **Browser:** Any modern browser with Web Crypto API (Chrome, Firefox, Safari, Edge)
- **Wolfronix Engine:** v2.4.1+

## License

MIT License — see [LICENSE](./LICENSE) for details.

## Links

- [npm Package](https://www.npmjs.com/package/wolfronix-sdk)
- [GitHub](https://github.com/wolfronix/sdk-javascript)
- [Report Issues](https://github.com/wolfronix/sdk-javascript/issues)
