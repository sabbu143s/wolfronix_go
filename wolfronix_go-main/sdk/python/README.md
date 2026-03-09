# Wolfronix SDK for Python

Official Python SDK for Wolfronix zero-knowledge encryption.

## Installation

```bash
pip install wolfronix-sdk
```

For WebSocket streaming support:

```bash
pip install wolfronix-sdk[websocket]
```

## Quick Start

```python
import asyncio
from wolfronix import Wolfronix, WolfronixConfig

async def main():
    wfx = Wolfronix(WolfronixConfig(
        base_url="https://your-server:9443",
        client_id="your_client_id",
        wolfronix_key="your_wolfronix_key",
        insecure=True,
    ))

    await wfx.register("user@example.com", "password123", enable_recovery=True)
    await wfx.login("user@example.com", "password123")

asyncio.run(main())
```

## Authentication

- `await register(email, password, enable_recovery=True, recovery_phrase=None)`
- `await login(email, password)`
- `await recover_account(email, recovery_phrase, new_password)`
- `await rotate_identity_keys(password, recovery_phrase=None)`
- `set_token(token, user_id=None)`
- `logout()`
- `is_authenticated()`
- `get_user_id()`
- `has_private_key()`

Notes:
- `register(..., enable_recovery=True)` adds recovery wrapping and returns recovery metadata on the response object.
- `rotate_identity_keys` currently raises `NOT_SUPPORTED` against current server API.

## Files

- `await encrypt(file_data, filename="file")`
- `await encrypt_resumable(file_data, filename="file.bin", chunk_size_bytes=10*1024*1024, existing_state=None)`
- `await decrypt(file_id, role="owner")`
- `await decrypt_chunked_to_buffer(manifest, role="owner")`
- `await decrypt_chunked_manifest(manifest, role="owner")`
- `await get_file_key(file_id)`
- `await list_files()`
- `await delete_file(file_id)`

Resumable returns:

```python
{
  "result": {
    "upload_id": "...",
    "filename": "...",
    "total_chunks": 100,
    "chunk_size_bytes": 10485760,
    "uploaded_chunks": 100,
    "chunk_file_ids": ["..."],
    "complete": True,
  },
  "state": {...}
}
```

## E2E 1:1 Chat

- `await get_public_key(user_id, client_id=None)`
- `await encrypt_message(text, recipient_id)`
- `await decrypt_message(packet_json)`

## PFS Ratchet (Double Ratchet style)

- `await create_pfs_prekey_bundle()`
- `await init_pfs_session(session_id, peer_bundle, as_initiator)`
- `export_pfs_session(session_id)`
- `import_pfs_session(session)`
- `await pfs_encrypt_message(session_id, plaintext)`
- `await pfs_decrypt_message(session_id, packet)`

## Group Sender-Key

- `await encrypt_group_message(text, group_id, recipient_ids)`
- `await decrypt_group_message(packet_json)`

## Server Message Encryption

- `await server_encrypt(message, layer=4)`
- `await server_decrypt(params)`
- `await server_encrypt_batch(messages, layer=4)`
- `await server_decrypt_batch_item(batch_result, index)`

## Streaming

- `await create_stream(direction, stream_key=None)`

## Admin Client

```python
from wolfronix import WolfronixAdmin, WolfronixAdminConfig

admin = WolfronixAdmin(WolfronixAdminConfig(
    base_url="https://your-server:9443",
    admin_key="your-admin-api-key",
    insecure=True,
))
```

- `await register_client(params)`
- `await list_clients()`
- `await get_client(client_id)`
- `await update_client(client_id, params)`
- `await deactivate_client(client_id)`
- `await health_check()`

## Errors

- `WolfronixError`
- `AuthenticationError`
- `ValidationError`
- `PermissionDeniedError`
- `FileNotFoundError`
- `NetworkError`

## Requirements

- Python 3.9+
- `httpx>=0.25.0`
- `cryptography>=41.0.0`
- `websockets>=12.0` (optional, streaming)