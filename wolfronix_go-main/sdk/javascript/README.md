# wolfronix-sdk

Official JavaScript/TypeScript SDK for Wolfronix zero-knowledge encryption.

## Features

- Client-side key generation and private key wrapping
- Optional 24-word recovery phrase on registration
- Account recovery flow (`recoverAccount`)
- File encryption/decryption
- Resumable chunked uploads for large files (`encryptResumable`)
- 1:1 E2E messaging (`encryptMessage` / `decryptMessage`)
- PFS ratchet messaging (`createPfsPreKeyBundle`, `initPfsSession`, `pfsEncryptMessage`, `pfsDecryptMessage`)
- Group sender-key messaging (`encryptGroupMessage`, `decryptGroupMessage`)
- Server-side message encryption APIs
- Streaming encryption/decryption over WebSocket
- Enterprise admin client management APIs

## Installation

```bash
npm install wolfronix-sdk
```

## Browser Usage

```html
<script src="https://unpkg.com/wolfronix-sdk/dist/index.global.js"></script>
<script>
  const wfx = new WolfronixSDK.default({
    baseUrl: 'https://your-server:9443',
    clientId: 'your-client-id',
    wolfronixKey: 'your-wolfronix-key'
  });
</script>
```

## Quick Start

```ts
import Wolfronix from 'wolfronix-sdk';

const wfx = new Wolfronix({
  baseUrl: 'https://your-server:9443',
  clientId: 'your-client-id',
  wolfronixKey: 'your-wolfronix-key'
});

await wfx.register('user@example.com', 'password123', { enableRecovery: true });
await wfx.login('user@example.com', 'password123');
```

## Authentication API

| Method | Returns |
|---|---|
| `register(email, password, options?)` | `Promise<AuthResponse & Partial<RecoverySetup>>` |
| `login(email, password)` | `Promise<AuthResponse>` |
| `recoverAccount(email, recoveryPhrase, newPassword)` | `Promise<AuthResponse>` |
| `rotateIdentityKeys(password, recoveryPhrase?)` | `Promise<{ success: boolean; message: string; recoveryPhrase?: string }>` |
| `setToken(token, userId?)` | `void` |
| `logout()` | `void` |
| `isAuthenticated()` | `boolean` |
| `getUserId()` | `string \| null` |
| `hasPrivateKey()` | `boolean` |

Notes:
- `register(..., { enableRecovery: true })` returns `recoveryPhrase` and `recoveryWords`.
- `rotateIdentityKeys` currently throws `NOT_SUPPORTED` on the current server API.

### Recovery Example

```ts
const reg = await wfx.register('user@example.com', 'password123', { enableRecovery: true });
console.log(reg.recoveryPhrase); // Save offline securely

await wfx.recoverAccount('user@example.com', reg.recoveryPhrase!, 'newPassword123');
```

## File API

| Method | Returns |
|---|---|
| `encrypt(file, filename?)` | `Promise<EncryptResponse>` |
| `encryptResumable(file, options?)` | `Promise<{ result: ChunkedEncryptResult; state: ResumableUploadState }>` |
| `decrypt(fileId, role?)` | `Promise<Blob>` |
| `decryptToBuffer(fileId, role?)` | `Promise<ArrayBuffer>` |
| `decryptChunkedToBuffer(manifest, role?)` | `Promise<ArrayBuffer>` |
| `decryptChunkedManifest(manifest, role?)` | `Promise<Blob>` |
| `getFileKey(fileId)` | `Promise<KeyPartResponse>` |
| `listFiles()` | `Promise<ListFilesResponse>` |
| `deleteFile(fileId)` | `Promise<DeleteResponse>` |

### Resumable Upload Example

```ts
const { result, state } = await wfx.encryptResumable(file, {
  chunkSizeBytes: 10 * 1024 * 1024,
  onProgress: (uploaded, total) => console.log(`${uploaded}/${total}`)
});

const manifest = {
  filename: result.filename,
  chunk_file_ids: result.chunk_file_ids
};

const mergedBlob = await wfx.decryptChunkedManifest(manifest);
```

## E2E Messaging API

| Method | Returns |
|---|---|
| `getPublicKey(userId, clientId?)` | `Promise<CryptoKey>` |
| `encryptMessage(text, recipientId)` | `Promise<string>` |
| `decryptMessage(packetString)` | `Promise<string>` |

## PFS Ratchet API

| Method | Returns |
|---|---|
| `createPfsPreKeyBundle()` | `Promise<PfsPreKeyBundle>` |
| `initPfsSession(sessionId, peerBundle, asInitiator)` | `Promise<PfsSessionState>` |
| `exportPfsSession(sessionId)` | `PfsSessionState` |
| `importPfsSession(session)` | `void` |
| `pfsEncryptMessage(sessionId, plaintext)` | `Promise<PfsMessagePacket>` |
| `pfsDecryptMessage(sessionId, packet)` | `Promise<string>` |

## Group Sender-Key API

| Method | Returns |
|---|---|
| `encryptGroupMessage(text, groupId, recipientIds)` | `Promise<string>` |
| `decryptGroupMessage(packetJson)` | `Promise<string>` |

## Server Message Encryption API

| Method | Returns |
|---|---|
| `serverEncrypt(message, options?)` | `Promise<ServerEncryptResult>` |
| `serverDecrypt(params)` | `Promise<string>` |
| `serverEncryptBatch(messages, options?)` | `Promise<ServerBatchEncryptResult>` |
| `serverDecryptBatchItem(batchResult, index)` | `Promise<string>` |

## Streaming API

| Method | Returns |
|---|---|
| `createStream(direction, streamKey?)` | `Promise<WolfronixStream>` |

## Admin API

```ts
import { WolfronixAdmin } from 'wolfronix-sdk';

const admin = new WolfronixAdmin({
  baseUrl: 'https://your-server:9443',
  adminKey: 'your-admin-api-key'
});
```

| Method | Returns |
|---|---|
| `registerClient(params)` | `Promise<RegisterClientResponse>` |
| `listClients()` | `Promise<ListClientsResponse>` |
| `getClient(clientId)` | `Promise<EnterpriseClient>` |
| `updateClient(clientId, params)` | `Promise<UpdateClientResponse>` |
| `deactivateClient(clientId)` | `Promise<DeactivateClientResponse>` |
| `healthCheck()` | `Promise<boolean>` |

## Errors

The SDK throws typed errors:
- `WolfronixError`
- `AuthenticationError`
- `FileNotFoundError`
- `PermissionDeniedError`
- `NetworkError`
- `ValidationError`

## Requirements

- Node.js 18+
- Modern browsers with Web Crypto API
- Wolfronix Engine v2.4.1+

## License

MIT