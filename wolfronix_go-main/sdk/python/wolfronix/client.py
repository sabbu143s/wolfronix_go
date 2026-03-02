"""
Main Wolfronix client — mirrors the TypeScript ``Wolfronix`` class.

Features:
  - Register / Login (zero-knowledge key wrapping)
  - File encrypt / decrypt (4-layer architecture, dual-key split)
  - E2E chat message encryption (RSA + AES hybrid)
  - Server-side message encryption (Layer 3 & 4)
  - Batch message encryption
  - WebSocket streaming encryption
  - Metrics & health check
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from io import BytesIO
from typing import Any, BinaryIO, Dict, List, Optional, Union
from urllib.parse import quote

import httpx

from .crypto import (
    decrypt_data,
    encrypt_data,
    export_key_to_pem,
    export_session_key,
    generate_key_pair,
    generate_session_key,
    import_key_from_pem,
    import_session_key,
    rsa_decrypt,
    rsa_decrypt_base64,
    rsa_encrypt,
    unwrap_private_key,
    wrap_private_key,
)
from .errors import (
    AuthenticationError,
    FileNotFoundError,
    NetworkError,
    PermissionDeniedError,
    ValidationError,
    WolfronixError,
)
from .types import (
    AuthResponse,
    DeleteResponse,
    EncryptMessagePacket,
    EncryptResponse,
    FileInfo,
    KeyPartResponse,
    ListFilesResponse,
    MetricsResponse,
    ServerBatchEncryptResult,
    ServerDecryptParams,
    ServerEncryptResult,
    WolfronixConfig,
)


class Wolfronix:
    """
    Main Wolfronix SDK client.

    Example::

        from wolfronix import Wolfronix

        wfx = Wolfronix(WolfronixConfig(
            base_url="https://wolfronix-server:9443",
            client_id="your-client-id",
            wolfronix_key="your-key",
            insecure=True,
        ))

        # Register
        result = await wfx.register("user@example.com", "password123")

        # Encrypt a file
        with open("document.pdf", "rb") as f:
            enc = await wfx.encrypt(f.read(), filename="document.pdf")
    """

    def __init__(self, config: Union[WolfronixConfig, str]):
        if isinstance(config, str):
            config = WolfronixConfig(base_url=config)

        self._config = config
        self._config.base_url = self._config.base_url.rstrip("/")

        # Auth state
        self._token: Optional[str] = None
        self._user_id: Optional[str] = None
        self._token_expiry: Optional[float] = None

        # Client-side keys (never stored on server in raw form)
        self._public_key = None  # RSAPublicKey
        self._private_key = None  # RSAPrivateKey
        self._public_key_pem: Optional[str] = None

    # ──────────────────────────────────────────────────────────────────────────
    # Properties
    # ──────────────────────────────────────────────────────────────────────────

    def has_private_key(self) -> bool:
        """Check whether the private key is loaded in memory."""
        return self._private_key is not None

    def is_authenticated(self) -> bool:
        """Check if the client has an active session."""
        if not self._token:
            return False
        if self._token_expiry and time.time() > self._token_expiry:
            return False
        return True

    def get_user_id(self) -> Optional[str]:
        """Get the current user ID."""
        return self._user_id

    # ──────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _get_headers(self, include_auth: bool = True) -> Dict[str, str]:
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self._config.client_id:
            headers["X-Client-ID"] = self._config.client_id
        if self._config.wolfronix_key:
            headers["X-Wolfronix-Key"] = self._config.wolfronix_key
        if include_auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
            if self._user_id:
                headers["X-User-ID"] = self._user_id
        return headers

    def _build_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._config.base_url,
            verify=not self._config.insecure,
            timeout=httpx.Timeout(self._config.timeout / 1000.0),
        )

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        body: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, str]] = None,
        include_auth: bool = True,
        response_type: str = "json",  # "json" | "bytes"
        extra_headers: Optional[Dict[str, str]] = None,
        unlimited_timeout: bool = False,
    ) -> Any:
        headers = self._get_headers(include_auth)
        if extra_headers:
            headers.update(extra_headers)

        last_error: Optional[Exception] = None

        for attempt in range(1, self._config.retries + 1):
            try:
                timeout = (
                    httpx.Timeout(None) if unlimited_timeout
                    else httpx.Timeout(self._config.timeout / 1000.0)
                )
                async with httpx.AsyncClient(
                    base_url=self._config.base_url,
                    verify=not self._config.insecure,
                    timeout=timeout,
                ) as client:
                    if files:
                        # Multipart upload — don't set Content-Type manually
                        resp = await client.request(
                            method,
                            endpoint,
                            headers=headers,
                            files=files,
                            data=data or {},
                        )
                    elif body is not None:
                        headers["Content-Type"] = "application/json"
                        resp = await client.request(
                            method,
                            endpoint,
                            headers=headers,
                            content=json.dumps(body),
                        )
                    else:
                        resp = await client.request(
                            method,
                            endpoint,
                            headers=headers,
                        )

                if resp.status_code == 401:
                    error_body = resp.json() if resp.content else {}
                    raise AuthenticationError(
                        error_body.get("error", "Authentication failed")
                    )
                if resp.status_code == 403:
                    error_body = resp.json() if resp.content else {}
                    raise PermissionDeniedError(
                        error_body.get("error", "Permission denied")
                    )
                if resp.status_code == 404:
                    raise FileNotFoundError(endpoint)

                if not resp.is_success:
                    error_body = {}
                    try:
                        error_body = resp.json()
                    except Exception:
                        pass
                    raise WolfronixError(
                        error_body.get("error", f"Request failed with status {resp.status_code}"),
                        "REQUEST_ERROR",
                        resp.status_code,
                        error_body,
                    )

                if response_type == "bytes":
                    return resp.content
                return resp.json()

            except (
                AuthenticationError,
                PermissionDeniedError,
                FileNotFoundError,
            ):
                raise
            except Exception as exc:
                last_error = exc
                if attempt < self._config.retries:
                    await asyncio.sleep((2 ** attempt) * 0.1)
                    continue

        raise last_error or NetworkError("Request failed after retries")

    def _ensure_authenticated(self) -> None:
        if not self._token:
            raise AuthenticationError(
                "Not authenticated. Call login() or register() first."
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Authentication
    # ──────────────────────────────────────────────────────────────────────────

    async def register(self, email: str, password: str) -> AuthResponse:
        """
        Register a new user.

        1. Generates RSA-2048 key pair client-side
        2. Wraps private key with password (PBKDF2 + AES-256-GCM)
        3. Sends wrapped key + public key to server (zero-knowledge)

        Example::

            result = await wfx.register("user@example.com", "password123")
        """
        if not email or not password:
            raise ValidationError("Email and password are required")

        # 1. Generate RSA Key Pair
        key_pair = generate_key_pair()

        # 2. Export Public Key
        public_key_pem = export_key_to_pem(key_pair.public_key, "public")

        # 3. Wrap Private Key
        wrapped = wrap_private_key(key_pair.private_key, password)

        # 4. Register with Server
        response = await self._request(
            "POST",
            "/api/v1/keys/register",
            body={
                "client_id": self._config.client_id,
                "user_id": email,
                "public_key_pem": public_key_pem,
                "encrypted_private_key": wrapped.encrypted_key,
                "salt": wrapped.salt,
            },
            include_auth=False,
        )

        if response.get("success"):
            self._user_id = email
            self._public_key = key_pair.public_key
            self._private_key = key_pair.private_key
            self._public_key_pem = public_key_pem
            self._token = "zk-session"

        return AuthResponse(
            success=response.get("success", False),
            user_id=response.get("user_id", email),
            token=self._token or "",
            message=response.get("message", ""),
        )

    async def login(self, email: str, password: str) -> AuthResponse:
        """
        Login with existing credentials.

        1. Fetches encrypted private key from server
        2. Unwraps it client-side with your password
        3. Private key never leaves the client

        Example::

            result = await wfx.login("user@example.com", "password123")
        """
        if not email or not password:
            raise ValidationError("Email and password are required")

        # 1. Fetch Encrypted Keys
        response = await self._request(
            "POST",
            "/api/v1/keys/login",
            body={
                "client_id": self._config.client_id,
                "user_id": email,
            },
            include_auth=False,
        )

        if not response.get("encrypted_private_key") or not response.get("salt"):
            raise AuthenticationError("Invalid credentials or keys not found")

        # 2. Unwrap Private Key
        try:
            self._private_key = unwrap_private_key(
                response["encrypted_private_key"],
                password,
                response["salt"],
            )
        except Exception:
            raise AuthenticationError("Invalid password (decryption failed)")

        # 3. Import Public Key
        self._public_key_pem = response["public_key_pem"]
        self._public_key = import_key_from_pem(response["public_key_pem"], "public")
        self._user_id = email
        self._token = "zk-session"

        return AuthResponse(
            success=True,
            user_id=email,
            token=self._token,
            message="Logged in successfully",
        )

    def set_token(self, token: str, user_id: Optional[str] = None) -> None:
        """Set authentication token directly (useful for server-side apps)."""
        self._token = token
        self._user_id = user_id
        self._token_expiry = time.time() + 86400  # 24h

    def logout(self) -> None:
        """Clear authentication state."""
        self._token = None
        self._user_id = None
        self._token_expiry = None
        self._public_key = None
        self._private_key = None
        self._public_key_pem = None

    # ──────────────────────────────────────────────────────────────────────────
    # File Operations
    # ──────────────────────────────────────────────────────────────────────────

    async def encrypt(
        self,
        file_data: Union[bytes, BinaryIO],
        filename: str = "file",
    ) -> EncryptResponse:
        """
        Encrypt and store a file.

        Args:
            file_data: File content as ``bytes`` or a file-like object.
            filename: Original filename (used for metadata).

        Example::

            with open("document.pdf", "rb") as f:
                result = await wfx.encrypt(f.read(), filename="document.pdf")
            print(result.file_id)
        """
        self._ensure_authenticated()

        if not self._public_key_pem:
            raise WolfronixError("Public key not available. Is user logged in?")

        if isinstance(file_data, (bytes, bytearray)):
            content = file_data
        else:
            content = file_data.read()

        files = {"file": (filename, content)}
        data = {
            "user_id": self._user_id or "",
            "client_public_key": self._public_key_pem,
        }

        response = await self._request(
            "POST",
            "/api/v1/encrypt",
            files=files,
            data=data,
            unlimited_timeout=True,
        )

        return EncryptResponse(
            status=response.get("status", ""),
            file_id=str(response.get("file_id", "")),
            file_size=response.get("file_size", 0),
            enc_time_ms=response.get("enc_time_ms", 0),
            upload_ms=response.get("upload_ms"),
            read_ms=response.get("read_ms"),
            encrypt_ms=response.get("encrypt_ms"),
            store_ms=response.get("store_ms"),
            total_ms=response.get("total_ms"),
        )

    async def decrypt(self, file_id: str, role: str = "owner") -> bytes:
        """
        Decrypt and retrieve a file (zero-knowledge flow).

        Flow:
          1. GET  /api/v1/files/{id}/key    → encrypted key_part_a
          2. Decrypt key_part_a client-side  (RSA-OAEP)
          3. POST /api/v1/files/{id}/decrypt → decrypted file bytes

        The private key NEVER leaves the client.

        Returns:
            Raw decrypted file bytes.
        """
        self._ensure_authenticated()
        if not file_id:
            raise ValidationError("File ID is required")
        if not self._private_key:
            raise WolfronixError("Private key not available. Is user logged in?")

        # Step 1: Fetch encrypted key_part_a
        key_resp = await self.get_file_key(file_id)

        # Step 2: Decrypt key_part_a client-side
        decrypted_key_a = rsa_decrypt_base64(key_resp.key_part_a, self._private_key)

        # Step 3: Send decrypted_key_a to server
        return await self._request(
            "POST",
            f"/api/v1/files/{file_id}/decrypt",
            body={"decrypted_key_a": decrypted_key_a, "user_role": role},
            response_type="bytes",
        )

    async def get_file_key(self, file_id: str) -> KeyPartResponse:
        """Fetch the encrypted key_part_a for a file."""
        self._ensure_authenticated()
        if not file_id:
            raise ValidationError("File ID is required")

        resp = await self._request("GET", f"/api/v1/files/{file_id}/key")
        return KeyPartResponse(
            file_id=resp.get("file_id", ""),
            key_part_a=resp.get("key_part_a", ""),
            message=resp.get("message", ""),
        )

    async def list_files(self) -> ListFilesResponse:
        """List all encrypted files for the current user."""
        self._ensure_authenticated()
        files_raw = await self._request("GET", "/api/v1/files")
        files_raw = files_raw or []
        files = [
            FileInfo(
                file_id=f.get("id", ""),
                original_name=f.get("name", ""),
                encrypted_size=f.get("size_bytes", 0),
                created_at=f.get("date", ""),
            )
            for f in files_raw
        ]
        return ListFilesResponse(success=True, files=files, total=len(files))

    async def delete_file(self, file_id: str) -> DeleteResponse:
        """Delete an encrypted file."""
        self._ensure_authenticated()
        if not file_id:
            raise ValidationError("File ID is required")
        resp = await self._request("DELETE", f"/api/v1/files/{file_id}")
        return DeleteResponse(
            success=resp.get("success", False),
            message=resp.get("message", ""),
        )

    # ──────────────────────────────────────────────────────────────────────────
    # E2E Chat Encryption
    # ──────────────────────────────────────────────────────────────────────────

    async def get_public_key(self, user_id: str, client_id: Optional[str] = None) -> str:
        """
        Get another user's public key PEM (for E2E encryption).

        Args:
            user_id: The recipient's user ID.
            client_id: Override the configured client_id.

        Returns:
            PEM-encoded public key string.
        """
        self._ensure_authenticated()
        cid = client_id or self._config.client_id
        if not cid:
            raise ValidationError(
                "clientId is required for get_public_key(). Set it in config or pass as argument."
            )
        resp = await self._request(
            "GET",
            f"/api/v1/keys/public/{quote(cid, safe='')}/{quote(user_id, safe='')}",
        )
        return resp["public_key_pem"]

    async def encrypt_message(self, text: str, recipient_id: str) -> str:
        """
        Encrypt a message for a recipient (Hybrid: RSA + AES).

        Returns:
            JSON string packet to send via chat.
        """
        self._ensure_authenticated()

        # 1. Get Recipient's Public Key
        recipient_pub_pem = await self.get_public_key(recipient_id)
        recipient_pub_key = import_key_from_pem(recipient_pub_pem, "public")

        # 2. Generate Ephemeral Session Key
        session_key = generate_session_key()

        # 3. Encrypt Message with Session Key
        encrypted_msg, iv = encrypt_data(text, session_key)

        # 4. Encrypt Session Key with Recipient's RSA Key
        raw_key = export_session_key(session_key)
        encrypted_session_key = rsa_encrypt(raw_key, recipient_pub_key)

        # 5. Pack
        packet = EncryptMessagePacket(
            key=encrypted_session_key,
            iv=iv,
            msg=encrypted_msg,
        )
        return json.dumps({"key": packet.key, "iv": packet.iv, "msg": packet.msg})

    async def decrypt_message(self, packet_json: str) -> str:
        """
        Decrypt a message packet received from chat.

        Args:
            packet_json: JSON string packet from ``encrypt_message()``.

        Returns:
            Decrypted plaintext message.
        """
        self._ensure_authenticated()
        if not self._private_key:
            raise WolfronixError("Private key not available. Is user logged in?")

        try:
            packet = json.loads(packet_json)
        except json.JSONDecodeError:
            raise ValidationError("Invalid message packet format")

        if not packet.get("key") or not packet.get("iv") or not packet.get("msg"):
            raise ValidationError("Invalid message packet structure")

        try:
            # 1. Decrypt Session Key with Private Key
            raw_session_key = rsa_decrypt(packet["key"], self._private_key)

            # 2. Import Session Key
            session_key = import_session_key(raw_session_key)

            # 3. Decrypt Message Body
            return decrypt_data(packet["msg"], packet["iv"], session_key)
        except Exception:
            raise WolfronixError(
                "Decryption failed. You may not be the intended recipient."
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Server-Side Message Encryption (Dual-Key Split)
    # ──────────────────────────────────────────────────────────────────────────

    async def server_encrypt(
        self, message: str, *, layer: int = 4
    ) -> ServerEncryptResult:
        """
        Encrypt a message via the Wolfronix server (dual-key split).

        The server generates an AES key, encrypts the message, and splits the key —
        you get key_part_a, the server holds key_part_b.

        Args:
            message: Plaintext message to encrypt.
            layer: ``3`` = AES only (full key returned), ``4`` = dual-key split (default).

        Example::

            result = await wfx.server_encrypt("Hello, World!")
        """
        self._ensure_authenticated()
        if not message:
            raise ValidationError("Message is required")

        resp = await self._request(
            "POST",
            "/api/v1/messages/encrypt",
            body={"message": message, "user_id": self._user_id, "layer": layer},
        )
        return ServerEncryptResult(
            encrypted_message=resp.get("encrypted_message", ""),
            nonce=resp.get("nonce", ""),
            key_part_a=resp.get("key_part_a", ""),
            message_tag=resp.get("message_tag", ""),
            timestamp=resp.get("timestamp", 0),
        )

    async def server_decrypt(self, params: ServerDecryptParams) -> str:
        """
        Decrypt a message previously encrypted via ``server_encrypt()``.

        Returns:
            Decrypted plaintext message.
        """
        self._ensure_authenticated()
        if not params.encrypted_message or not params.nonce or not params.key_part_a:
            raise ValidationError(
                "encrypted_message, nonce, and key_part_a are required"
            )

        resp = await self._request(
            "POST",
            "/api/v1/messages/decrypt",
            body={
                "encrypted_message": params.encrypted_message,
                "nonce": params.nonce,
                "key_part_a": params.key_part_a,
                "message_tag": params.message_tag or "",
                "user_id": self._user_id,
            },
        )
        return resp.get("message", "")

    async def server_encrypt_batch(
        self,
        messages: List[Dict[str, str]],
        *,
        layer: int = 4,
    ) -> ServerBatchEncryptResult:
        """
        Encrypt multiple messages in a single round-trip (batch).

        All messages share one AES key (different nonce per message).

        Args:
            messages: List of ``{"id": "...", "message": "..."}`` dicts (max 100).
            layer: ``3`` or ``4`` (default: ``4``).

        Example::

            result = await wfx.server_encrypt_batch([
                {"id": "msg1", "message": "Hello"},
                {"id": "msg2", "message": "World"},
            ])
        """
        self._ensure_authenticated()
        if not messages:
            raise ValidationError("At least one message is required")
        if len(messages) > 100:
            raise ValidationError("Maximum 100 messages per batch")

        resp = await self._request(
            "POST",
            "/api/v1/messages/batch/encrypt",
            body={"messages": messages, "user_id": self._user_id, "layer": layer},
        )
        return ServerBatchEncryptResult(
            results=resp.get("results", []),
            key_part_a=resp.get("key_part_a", ""),
            batch_tag=resp.get("batch_tag", ""),
            timestamp=resp.get("timestamp", 0),
        )

    async def server_decrypt_batch_item(
        self,
        batch_result: ServerBatchEncryptResult,
        index: int,
    ) -> str:
        """
        Decrypt a single message from a batch result.

        Args:
            batch_result: The batch encrypt result.
            index: Index of the message to decrypt.
        """
        if index < 0 or index >= len(batch_result.results):
            raise ValidationError("Invalid batch index")

        item = batch_result.results[index]
        return await self.server_decrypt(
            ServerDecryptParams(
                encrypted_message=item["encrypted_message"],
                nonce=item["nonce"],
                key_part_a=batch_result.key_part_a,
                message_tag=batch_result.batch_tag,
            )
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Real-Time Streaming Encryption (WebSocket)
    # ──────────────────────────────────────────────────────────────────────────

    async def create_stream(
        self,
        direction: str,  # "encrypt" | "decrypt"
        stream_key: Optional[Dict[str, str]] = None,
    ) -> "WolfronixStream":
        """
        Create a streaming encryption/decryption session over WebSocket.

        Args:
            direction: ``"encrypt"`` or ``"decrypt"``.
            stream_key: Required for decrypt — ``{"key_part_a": "...", "stream_tag": "..."}``.

        Example::

            stream = await wfx.create_stream("encrypt")
            encrypted = await stream.send("Hello chunk 1")
            summary = await stream.end()
            # Save stream.key_part_a and stream.stream_tag for decryption
        """
        self._ensure_authenticated()
        if direction == "decrypt" and not stream_key:
            raise ValidationError(
                "stream_key (key_part_a + stream_tag) is required for decrypt streams"
            )

        stream = WolfronixStream(self._config, self._user_id or "")
        await stream.connect(direction, stream_key)
        return stream

    # ──────────────────────────────────────────────────────────────────────────
    # Metrics & Status
    # ──────────────────────────────────────────────────────────────────────────

    async def get_metrics(self) -> MetricsResponse:
        """Get encryption/decryption metrics."""
        self._ensure_authenticated()
        resp = await self._request("GET", "/api/v1/metrics/summary")
        return MetricsResponse(
            success=resp.get("success", False),
            total_encryptions=resp.get("total_encryptions", 0),
            total_decryptions=resp.get("total_decryptions", 0),
            total_bytes_encrypted=resp.get("total_bytes_encrypted", 0),
            total_bytes_decrypted=resp.get("total_bytes_decrypted", 0),
        )

    async def health_check(self) -> bool:
        """Check if the server is healthy."""
        try:
            await self._request(
                "GET", "/health", include_auth=False
            )
            return True
        except Exception:
            return False


# ── WebSocket Streaming ──────────────────────────────────────────────────────

class WolfronixStream:
    """
    Real-time streaming encryption/decryption over WebSocket.
    Each chunk is individually encrypted with AES-256-GCM using counter-based nonces.

    Example::

        stream = await wfx.create_stream("encrypt")
        encrypted_chunk = await stream.send("Hello chunk 1")
        summary = await stream.end()
    """

    def __init__(self, config: WolfronixConfig, user_id: str):
        self._config = config
        self._user_id = user_id
        self._ws = None
        self._seq_counter = 0

        # Public — available after encrypt stream init
        self.key_part_a: Optional[str] = None
        self.stream_tag: Optional[str] = None

    async def connect(
        self,
        direction: str,
        stream_key: Optional[Dict[str, str]] = None,
    ) -> None:
        """Connect and initialize the stream session (internal)."""
        try:
            import websockets  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "WebSocket streaming requires the 'websockets' package. "
                "Install it with: pip install websockets"
            )

        # Build WebSocket URL
        ws_base = self._config.base_url.replace("https://", "wss://").replace(
            "http://", "ws://"
        )
        params = []
        if self._config.wolfronix_key:
            params.append(f"wolfronix_key={self._config.wolfronix_key}")
        if self._config.client_id:
            params.append(f"client_id={self._config.client_id}")
        qs = "&".join(params)
        ws_url = f"{ws_base}/api/v1/stream?{qs}"

        ssl_context = None
        if self._config.insecure:
            import ssl as _ssl

            ssl_context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = _ssl.CERT_NONE

        self._ws = await websockets.connect(ws_url, ssl=ssl_context)

        # Send init
        init_msg: Dict[str, str] = {"type": "init", "direction": direction}
        if direction == "decrypt" and stream_key:
            init_msg["key_part_a"] = stream_key["key_part_a"]
            init_msg["stream_tag"] = stream_key["stream_tag"]

        await self._ws.send(json.dumps(init_msg))

        # Wait for init_ack
        raw = await self._ws.recv()
        msg = json.loads(raw)
        if msg.get("type") == "error":
            raise WolfronixError(msg.get("error", "Stream init failed"))
        if msg.get("type") == "init_ack":
            self.key_part_a = msg.get("key_part_a")
            self.stream_tag = msg.get("stream_tag")

    async def send(self, data: str) -> str:
        """
        Send a data chunk for encryption/decryption.

        Args:
            data: String data (will be base64-encoded before sending).

        Returns:
            Processed (encrypted/decrypted) chunk as base64.
        """
        if not self._ws:
            raise WolfronixError("Stream not connected")

        b64_data = base64.b64encode(data.encode("utf-8")).decode("utf-8")
        seq = self._seq_counter
        self._seq_counter += 1

        await self._ws.send(json.dumps({"type": "data", "data": b64_data}))

        # Wait for response
        raw = await self._ws.recv()
        msg = json.loads(raw)
        if msg.get("type") == "error":
            raise WolfronixError(msg.get("error", "Stream error"))
        return msg.get("data", "")

    async def send_binary(self, buffer: bytes) -> str:
        """
        Send raw binary data for encryption/decryption.

        Args:
            buffer: Raw bytes to process.

        Returns:
            Processed chunk as base64.
        """
        b64 = base64.b64encode(buffer).decode("utf-8")
        if not self._ws:
            raise WolfronixError("Stream not connected")
        seq = self._seq_counter
        self._seq_counter += 1
        await self._ws.send(json.dumps({"type": "data", "data": b64}))
        raw = await self._ws.recv()
        msg = json.loads(raw)
        if msg.get("type") == "error":
            raise WolfronixError(msg.get("error", "Stream error"))
        return msg.get("data", "")

    async def end(self) -> Dict[str, int]:
        """
        End the stream session.

        Returns:
            ``{"chunks_processed": N}``
        """
        if not self._ws:
            return {"chunks_processed": self._seq_counter}

        await self._ws.send(json.dumps({"type": "end"}))

        try:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=5.0)
            msg = json.loads(raw)
            chunks = msg.get("chunks_processed", self._seq_counter)
        except Exception:
            chunks = self._seq_counter

        await self._ws.close()
        self._ws = None
        return {"chunks_processed": chunks}

    async def close(self) -> None:
        """Close the stream immediately without sending an end message."""
        if self._ws:
            await self._ws.close()
            self._ws = None


# ── Factory ──────────────────────────────────────────────────────────────────

def create_client(config: Union[WolfronixConfig, str]) -> Wolfronix:
    """
    Create a new Wolfronix client.

    Example::

        from wolfronix import create_client, WolfronixConfig

        wfx = create_client(WolfronixConfig(
            base_url="https://wolfronix-server:9443",
            client_id="your-client-id",
        ))
    """
    return Wolfronix(config)
