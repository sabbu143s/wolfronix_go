# wolfronix-sdk

Official JavaScript/TypeScript SDK for Wolfronix - Zero-knowledge encryption made simple.

[![npm version](https://badge.fury.io/js/wolfronix-sdk.svg)](https://www.npmjs.com/package/wolfronix-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔐 **Zero-Knowledge Encryption** - Keys generated client-side, never leave your device
- 🏢 **Enterprise Ready** - Seamless integration with your existing storage
- 🚀 **Simple API** - Encrypt files in 2 lines of code
- 📦 **TypeScript Native** - Full type definitions included
- 🌐 **Universal** - Works in Node.js 18+ and modern browsers
- 🔄 **Auto Retry** - Built-in retry logic with exponential backoff

## Backend Integration (Enterprise Mode)

To use this SDK, your backend API must implement 3 storage endpoints that Wolfronix will call:

1.  **POST** `/wolfronix/files/upload` - Store encrypted file + metadata
2.  **GET** `/wolfronix/files/{id}` - Retrieve metadata
3.  **GET** `/wolfronix/files/{id}/data` - Retrieve encrypted file blob

Wolfronix handles all encryption/decryption keys and logic; you only handle the encrypted blobs.


## Installation

```bash
npm install wolfronix-sdk
# or
yarn add wolfronix-sdk
# or
pnpm add wolfronix-sdk
```

## Quick Start

```typescript
import Wolfronix from 'wolfronix-sdk';

// Initialize client
const wfx = new Wolfronix({
  baseUrl: 'https://your-wolfronix-server:5002',
  clientId: 'your-enterprise-client-id',
  wolfronixKey: 'your-api-key'
});

// Register (First time only) - Generates keys client-side
await wfx.register('user@example.com', 'password123');

// Login (Subsequent visits)
await wfx.login('user@example.com', 'password123');

// Encrypt a file
const result = await wfx.encrypt(file);
console.log('Encrypted! File ID:', result.file_id);

// Decrypt a file
const decrypted = await wfx.decrypt(result.file_id);
```

## Usage Examples

### Browser (React, Vue, Angular, etc.)

```typescript
import Wolfronix from 'wolfronix-sdk';

const wfx = new Wolfronix('https://wolfronix-server:5002');

// With file input
const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
  const file = event.target.files?.[0];
  if (!file) return;

  try {
    const { file_id } = await wfx.encrypt(file);
    console.log('File encrypted with your private key:', file_id);
  } catch (error) {
    console.error('Encryption failed:', error);
  }
};

// Download decrypted file
const handleDownload = async (fileId: string, filename: string) => {
  const blob = await wfx.decrypt(fileId);
  
  // Create download link
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};
```

### Node.js

```typescript
import Wolfronix from 'wolfronix-sdk';
import * as fs from 'fs';

const wfx = new Wolfronix({
  baseUrl: 'https://wolfronix-server:5002',
  clientId: 'your-client-id',
  wolfronixKey: 'your-api-key',
  insecure: true // For self-signed certs in development
});

async function main() {
  // Login
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

### 💬 E2E Encrypted Chat Integration

Turn any chat app into a secure, end-to-end encrypted messenger in minutes.

**Sender (Alice):**
```typescript
// 1. Get Bob's Public Key & Encrypt Message
const securePacket = await wfx.encryptMessage("Secret details at 5 PM", "bob_user_id");

// 2. Send 'securePacket' string via your normal chat API (Socket.io, Firebase, etc.)
chatSocket.emit('message', {
  to: 'bob',
  text: securePacket // Valid JSON string
});
```

**Recipient (Bob):**
```typescript
// 1. Receive message from chat server
chatSocket.on('message', async (msg) => {
  try {
    // 2. Decrypt locally with Bob's Private Key
    const plainText = await wfx.decryptMessage(msg.text);
    console.log("Decrypted:", plainText);
  } catch (err) {
    console.error("Could not decrypt message");
  }
});
```

**Features:**
- **Hybrid Encryption:** Uses AES-256 for messages + RSA-2048 for key exchange (Fast & Secure).
- **Zero-Knowledge:** Your chat server only sees encrypted packets.
- **Universal:** Works with any backend (Socket.io, Firebase, PostgreSQL, etc).

## API Reference

### Constructor

```typescript
new Wolfronix(config: WolfronixConfig | string)
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | string | required | Wolfronix server URL |
| `clientId` | string | `''` | Enterprise client ID |
| `wolfronixKey` | string | `''` | API key for X-Wolfronix-Key auth |
| `timeout` | number | `30000` | Request timeout (ms) |
| `retries` | number | `3` | Max retry attempts |
| `insecure` | boolean | `false` | Skip SSL verification (Node.js: uses undici Agent, or set `NODE_TLS_REJECT_UNAUTHORIZED=0`) |

### Authentication

| Method | Description |
|--------|-------------|
| `register(email, password)` | Register new user |
| `login(email, password)` | Login existing user |
| `setToken(token, userId?)` | Set auth token directly |
| `logout()` | Clear authentication |
| `isAuthenticated()` | Check auth status |
| `getUserId()` | Get current user ID |

### File Operations

| Method | Description |
|--------|-------------|
| `encrypt(file, filename?)` | Encrypt and store file |
| `decrypt(fileId, role?)` | Decrypt file (zero-knowledge, returns Blob) |
| `decryptToBuffer(fileId, role?)` | Decrypt file (zero-knowledge, returns ArrayBuffer) |
| `getFileKey(fileId)` | Get encrypted key_part_a for client-side decryption |
| `listFiles()` | List user's encrypted files |
| `deleteFile(fileId)` | Delete encrypted file |

### E2E Chat Encryption

| Method | Description |
|--------|-------------|
| `getPublicKey(userId, clientId?)` | Fetch a user's RSA public key |
| `encryptMessage(text, recipientId)` | Encrypt text for a recipient (returns packet string) |
| `decryptMessage(packetString)` | Decrypt a received message packet |

### Utility

| Method | Description |
|--------|-------------|
| `getMetrics()` | Get encryption/decryption stats |
| `healthCheck()` | Check server availability |

## Security Architecture (v2.0)

### Zero-Knowledge Decryption Flow

In v2.0, the private key **never leaves the client**. The decrypt flow works as follows:

```
Client                              Wolfronix Server
  │                                       │
  │  GET /files/{id}/key                  │
  │──────────────────────────────────────>│
  │  { key_part_a: "<RSA-OAEP encrypted>"}│
  │<──────────────────────────────────────│
  │                                       │
  │  [Decrypt key_part_a locally          │
  │   with private key (RSA-OAEP)]        │
  │                                       │
  │  POST /files/{id}/decrypt             │
  │  { decrypted_key_a: "<base64>" }      │
  │──────────────────────────────────────>│
  │                                       │
  │  [Server combines key_a + key_b,      │
  │   decrypts with AES-256-GCM]         │
  │                                       │
  │  <decrypted file bytes>               │
  │<──────────────────────────────────────│
```

### Key Security Properties
- **AES-256-GCM** authenticated encryption (tamper-proof, replaces AES-CTR)
- **RSA-OAEP** with SHA-256 for key transport (replaces PKCS1v15)
- **API key authentication** via `X-Wolfronix-Key` header on all endpoints
- **Configurable CORS** origins (no more wildcard `*`)
- **Dual-key split**: AES key split in half, each half encrypted with different RSA key
- **Zero-knowledge key wrapping**: Private keys wrapped with PBKDF2-derived keys, server never sees raw private keys

## Error Handling

The SDK provides specific error types for different scenarios:

```typescript
import Wolfronix, { 
  WolfronixError,
  AuthenticationError,
  FileNotFoundError,
  PermissionDeniedError,
  NetworkError,
  ValidationError
} from 'wolfronix-sdk';

try {
  await wfx.encrypt(file);
} catch (error) {
  if (error instanceof AuthenticationError) {
    // Token expired, redirect to login
    router.push('/login');
  } else if (error instanceof FileNotFoundError) {
    // File doesn't exist
    showToast('File not found');
  } else if (error instanceof PermissionDeniedError) {
    // Not your file
    showToast('Access denied');
  } else if (error instanceof NetworkError) {
    // Server unreachable
    showToast('Connection failed. Retrying...');
  } else if (error instanceof ValidationError) {
    // Invalid input
    showToast(error.message);
  } else {
    // Unknown error
    console.error('Unexpected error:', error);
  }
}
```

## TypeScript Support

The SDK is written in TypeScript and includes full type definitions:

```typescript
import Wolfronix, {
  WolfronixConfig,
  AuthResponse,
  EncryptResponse,
  FileInfo,
  ListFilesResponse,
  MetricsResponse
} from 'wolfronix-sdk';

// All methods are fully typed
const config: WolfronixConfig = {
  baseUrl: 'https://server:5002',
  clientId: 'my-client',
  wolfronixKey: 'my-api-key'
};

const wfx = new Wolfronix(config);
const response: EncryptResponse = await wfx.encrypt(file);
```

## React Hook Example

```typescript
// useWolfronix.ts
import { useState, useCallback, useMemo } from 'react';
import Wolfronix, { FileInfo as WolfronixFile } from 'wolfronix-sdk';

export function useWolfronix(baseUrl: string, clientId?: string, wolfronixKey?: string) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [files, setFiles] = useState<WolfronixFile[]>([]);

  const client = useMemo(() => new Wolfronix({ baseUrl, clientId, wolfronixKey }), [baseUrl, clientId, wolfronixKey]);

  const login = useCallback(async (email: string, password: string) => {
    setIsLoading(true);
    setError(null);
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
    setError(null);
    try {
      const result = await client.encrypt(file);
      await refreshFiles();
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
    setError(null);
    try {
      return await client.decrypt(fileId);
    } catch (e) {
      setError(e as Error);
      throw e;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  const refreshFiles = useCallback(async () => {
    const { files } = await client.listFiles();
    setFiles(files);
  }, [client]);

  return {
    client,
    isLoading,
    error,
    files,
    login,
    encrypt,
    decrypt,
    refreshFiles
  };
}

// Usage in component
function FileManager() {
  const { files, encrypt, decrypt, isLoading } = useWolfronix(
    'https://wolfronix:5002',
    'my-client-id'
  );

  return (
    <div>
      <input type="file" onChange={(e) => encrypt(e.target.files![0])} />
      {isLoading && <Spinner />}
      {files.map(f => (
        <div key={f.file_id} onClick={() => decrypt(f.file_id)}>
          {f.original_name}
        </div>
      ))}
    </div>
  );
}
```

## Real-World Use Cases

Wolfronix can be integrated into **any application** that handles sensitive data:

| Industry | Application | How Wolfronix Helps |
|----------|------------|---------------------|
| 🏥 **Healthcare** | Patient records, lab reports | HIPAA-compliant encryption at rest |
| 🏦 **Finance** | Invoices, tax docs, receipts | End-to-end encrypted banking documents |
| ⚖️ **Legal** | Contracts, case files | Zero-knowledge confidential storage |
| ☁️ **Cloud Storage** | Drive/Dropbox alternatives | Encrypted file vault with user-owned keys |
| 🏢 **Enterprise** | HR records, internal docs | Per-employee encryption isolation |
| 🎓 **Education** | Exam papers, student data | Tamper-proof academic records |
| 💬 **Messaging** | File attachments | Encrypted file sharing in chat apps |
| 🛒 **E-commerce** | Order docs, payment receipts | PCI-compliant document storage |

## Requirements

- Node.js 18+ (for Node.js usage)
- Modern browser with Web Crypto API support

## License

MIT License - see [LICENSE](./LICENSE) for details.

## Links

- [Documentation](https://wolfronix.com/docs)
- [API Reference](https://wolfronix.com/docs/api)
- [GitHub](https://github.com/wolfronix/sdk-javascript)
- [Report Issues](https://github.com/wolfronix/sdk-javascript/issues)
