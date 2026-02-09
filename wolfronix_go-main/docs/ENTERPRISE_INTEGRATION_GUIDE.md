# 🔐 Wolfronix Enterprise Integration Guide

> **Zero-Knowledge Encryption for Your Application**

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Get Your API Key](#step-1-get-your-api-key)
3. [Install the SDK](#step-2-install-the-sdk)
4. [Initialize the Client](#step-3-initialize-the-client)
5. [Encrypt Files](#step-4-encrypt-files)
6. [Decrypt Files](#step-5-decrypt-files)
7. [List & Manage Files](#step-6-list--manage-files)
8. [Error Handling](#step-7-error-handling)
9. [Code Examples](#complete-code-examples)
10. [API Reference](#api-reference)

---

## Prerequisites

Before you begin, ensure you have:

- [ ] Node.js 16+ installed
- [ ] Your Wolfronix API Key (starts with `wfx_`)
- [ ] Access to Wolfronix server URL

---

## Step 1: Get Your API Key

Contact Wolfronix admin or generate from your dashboard:

```
API Key Format: wfx_XXXXXXXXXXXXXXXX
Server URL: https://your-server:9443
```

> ⚠️ **Keep your API key secure!** Never expose it in frontend code.

---

## Step 2: Install the SDK

```bash
# Using npm
npm install @wolfronix/sdk

# Using yarn
yarn add @wolfronix/sdk

# Using pnpm
pnpm add @wolfronix/sdk
```

---

## Step 3: Initialize the Client

### Basic Setup

```typescript
import Wolfronix from '@wolfronix/sdk';

const wfx = new Wolfronix({
  baseUrl: 'https://your-server:9443',
  clientId: 'your-company-name',
  insecure: true  // Set to false in production with valid SSL
});
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | string | required | Wolfronix server URL |
| `clientId` | string | `''` | Your company/client identifier |
| `timeout` | number | `30000` | Request timeout in ms |
| `retries` | number | `3` | Auto-retry count |
| `insecure` | boolean | `false` | Allow self-signed certs |

---

## Step 4: Encrypt Files

### Method A: Using API Key (Recommended for Enterprise)

```typescript
import Wolfronix from '@wolfronix/sdk';

const wfx = new Wolfronix({
  baseUrl: 'https://your-server:9443',
  clientId: 'your-company'
});

// Set your API key
wfx.setToken('wfx_your_api_key_here', 'user-123');

// Encrypt a file
async function encryptFile(file: File) {
  const result = await wfx.encrypt(file);
  
  console.log('File ID:', result.file_id);
  console.log('Size:', result.encrypted_size);
  
  return result.file_id;
}
```

### Method B: With User Authentication

```typescript
// Login first
await wfx.login('user@company.com', 'password');

// Then encrypt
const result = await wfx.encrypt(file);
```

### Input Types Supported

```typescript
// Browser File object
await wfx.encrypt(inputElement.files[0]);

// Blob
await wfx.encrypt(new Blob(['data']), 'filename.txt');

// Buffer (Node.js)
import * as fs from 'fs';
const buffer = fs.readFileSync('document.pdf');
await wfx.encrypt(buffer, 'document.pdf');

// ArrayBuffer
await wfx.encrypt(arrayBuffer, 'file.bin');
```

---

## Step 5: Decrypt Files

### Browser (Download File)

```typescript
async function downloadDecryptedFile(fileId: string, filename: string) {
  // Get decrypted blob
  const blob = await wfx.decrypt(fileId);
  
  // Create download link
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  
  // Cleanup
  URL.revokeObjectURL(url);
}
```

### Node.js (Save to Disk)

```typescript
import * as fs from 'fs';

async function saveDecryptedFile(fileId: string, outputPath: string) {
  const buffer = await wfx.decryptToBuffer(fileId);
  fs.writeFileSync(outputPath, Buffer.from(buffer));
}
```

### With Progress Tracking (Large Files)

```typescript
const blob = await wfx.decryptStream(fileId, (percent) => {
  console.log(`Download progress: ${percent}%`);
  progressBar.value = percent;
});
```

---

## Step 6: List & Manage Files

### List All Files

```typescript
const { files, total } = await wfx.listFiles();

files.forEach(file => {
  console.log(`${file.original_name} (${file.file_id})`);
  console.log(`  Size: ${file.encrypted_size} bytes`);
  console.log(`  Created: ${file.created_at}`);
});
```

### Delete a File

```typescript
await wfx.deleteFile('file-id-here');
console.log('File deleted successfully');
```

### Get Usage Metrics

```typescript
const metrics = await wfx.getMetrics();

console.log(`Total encryptions: ${metrics.total_encryptions}`);
console.log(`Total decryptions: ${metrics.total_decryptions}`);
console.log(`Bytes encrypted: ${metrics.total_bytes_encrypted}`);
```

---

## Step 7: Error Handling

```typescript
import Wolfronix, {
  AuthenticationError,
  FileNotFoundError,
  PermissionDeniedError,
  NetworkError,
  ValidationError
} from '@wolfronix/sdk';

try {
  await wfx.encrypt(file);
} catch (error) {
  if (error instanceof AuthenticationError) {
    // Invalid or expired API key
    console.error('Auth failed - check your API key');
  } 
  else if (error instanceof FileNotFoundError) {
    // File doesn't exist
    console.error('File not found');
  } 
  else if (error instanceof PermissionDeniedError) {
    // Not authorized to access this file
    console.error('Access denied');
  } 
  else if (error instanceof NetworkError) {
    // Server unreachable
    console.error('Network error - server offline?');
  } 
  else if (error instanceof ValidationError) {
    // Invalid input
    console.error('Invalid input:', error.message);
  }
}
```

---

## Complete Code Examples

### Example 1: Node.js Backend Service

```typescript
// wolfronix-service.ts
import Wolfronix from '@wolfronix/sdk';
import * as fs from 'fs';

class WolfronixService {
  private client: Wolfronix;

  constructor() {
    this.client = new Wolfronix({
      baseUrl: process.env.WOLFRONIX_URL || 'https://your-server:9443',
      clientId: process.env.WOLFRONIX_CLIENT_ID || 'your-company',
      insecure: process.env.NODE_ENV !== 'production'
    });

    // Set API key from environment
    this.client.setToken(
      process.env.WOLFRONIX_API_KEY!,
      'service-account'
    );
  }

  async encryptFile(filePath: string): Promise<string> {
    const buffer = fs.readFileSync(filePath);
    const filename = filePath.split('/').pop() || 'file';
    
    const result = await this.client.encrypt(buffer, filename);
    return result.file_id;
  }

  async decryptFile(fileId: string, outputPath: string): Promise<void> {
    const buffer = await this.client.decryptToBuffer(fileId);
    fs.writeFileSync(outputPath, Buffer.from(buffer));
  }

  async listFiles() {
    return this.client.listFiles();
  }
}

// Usage
const wolfronix = new WolfronixService();
const fileId = await wolfronix.encryptFile('./secret-document.pdf');
console.log('Encrypted:', fileId);
```

### Example 2: React Component

```tsx
// FileEncryptor.tsx
import React, { useState, useCallback } from 'react';
import Wolfronix from '@wolfronix/sdk';

const API_URL = 'https://your-server:9443';
const API_KEY = 'wfx_your_api_key'; // In production, fetch from backend

const wfx = new Wolfronix({ baseUrl: API_URL, clientId: 'my-app' });
wfx.setToken(API_KEY, 'user-1');

export function FileEncryptor() {
  const [status, setStatus] = useState<string>('');
  const [fileId, setFileId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleEncrypt = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    setStatus('🔐 Encrypting...');

    try {
      const result = await wfx.encrypt(file);
      setFileId(result.file_id);
      setStatus(`✅ Encrypted! ID: ${result.file_id}`);
    } catch (error) {
      setStatus(`❌ Error: ${(error as Error).message}`);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleDecrypt = useCallback(async () => {
    if (!fileId) return;

    setIsLoading(true);
    setStatus('🔓 Decrypting...');

    try {
      const blob = await wfx.decrypt(fileId);
      
      // Download the file
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'decrypted-file';
      a.click();
      URL.revokeObjectURL(url);
      
      setStatus('✅ File downloaded!');
    } catch (error) {
      setStatus(`❌ Error: ${(error as Error).message}`);
    } finally {
      setIsLoading(false);
    }
  }, [fileId]);

  return (
    <div style={{ padding: 20, fontFamily: 'sans-serif' }}>
      <h2>🔐 Wolfronix File Encryption</h2>
      
      <div style={{ marginBottom: 20 }}>
        <input 
          type="file" 
          onChange={handleEncrypt} 
          disabled={isLoading}
        />
      </div>

      {fileId && (
        <button onClick={handleDecrypt} disabled={isLoading}>
          Download Decrypted File
        </button>
      )}

      <p>{status}</p>
    </div>
  );
}
```

### Example 3: Express.js API Endpoint

```typescript
// routes/encryption.ts
import express from 'express';
import multer from 'multer';
import Wolfronix from '@wolfronix/sdk';

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

const wfx = new Wolfronix({
  baseUrl: process.env.WOLFRONIX_URL!,
  clientId: 'my-backend'
});
wfx.setToken(process.env.WOLFRONIX_API_KEY!, 'backend-service');

// POST /api/encrypt
router.post('/encrypt', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    const result = await wfx.encrypt(
      req.file.buffer,
      req.file.originalname
    );

    res.json({
      success: true,
      fileId: result.file_id,
      size: result.encrypted_size
    });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// GET /api/decrypt/:fileId
router.get('/decrypt/:fileId', async (req, res) => {
  try {
    const buffer = await wfx.decryptToBuffer(req.params.fileId);
    
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment');
    res.send(Buffer.from(buffer));
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// GET /api/files
router.get('/files', async (req, res) => {
  try {
    const { files } = await wfx.listFiles();
    res.json({ files });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

export default router;
```

---

## API Reference

### Authentication

| Method | Description |
|--------|-------------|
| `setToken(apiKey, userId)` | Set API key for enterprise mode |
| `login(email, password)` | Login with user credentials |
| `register(email, password)` | Register new user |
| `logout()` | Clear authentication |
| `isAuthenticated()` | Check if authenticated |

### File Operations

| Method | Description |
|--------|-------------|
| `encrypt(file, filename?)` | Encrypt and store file |
| `encryptStream(file, onProgress?)` | Encrypt with progress callback |
| `decrypt(fileId)` | Decrypt and return Blob |
| `decryptToBuffer(fileId)` | Decrypt and return ArrayBuffer |
| `decryptStream(fileId, onProgress?)` | Decrypt with progress callback |
| `listFiles()` | List all user's files |
| `deleteFile(fileId)` | Delete a file |

### Utility

| Method | Description |
|--------|-------------|
| `healthCheck()` | Check server status |
| `getMetrics()` | Get usage statistics |

---

## Environment Variables

```bash
# .env
WOLFRONIX_URL=https://your-server:9443
WOLFRONIX_API_KEY=wfx_your_api_key_here
WOLFRONIX_CLIENT_ID=your-company-name
```

---

## Support

- **Email**: support@wolfronix.com
- **Documentation**: https://docs.wolfronix.com
- **GitHub Issues**: https://github.com/wolfronix/sdk-javascript/issues

---

© 2026 Wolfronix. All rights reserved.
