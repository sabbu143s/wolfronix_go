"""
Type definitions for Wolfronix SDK.
Mirrors the TypeScript SDK types exactly.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

# Supported managed connector database types
DBType = Literal["supabase", "mongodb", "mysql", "firebase", "postgresql", "custom_api"]


@dataclass
class WolfronixConfig:
    """Configuration for the Wolfronix client."""

    base_url: str
    """Wolfronix server base URL"""

    client_id: str = ""
    """Your enterprise client ID (optional for self-hosted)"""

    wolfronix_key: str = ""
    """API key for authentication (X-Wolfronix-Key header)"""

    timeout: int = 30000
    """Request timeout in milliseconds (default: 30000)"""

    retries: int = 3
    """Retry failed requests (default: 3)"""

    insecure: bool = False
    """Skip SSL verification for self-signed certs (default: False)"""


@dataclass
class WolfronixAdminConfig:
    """Configuration for the Wolfronix admin client."""

    base_url: str
    """Wolfronix server base URL"""

    admin_key: str
    """Admin API key (X-Admin-Key header)"""

    timeout: int = 30000
    """Request timeout in milliseconds (default: 30000)"""

    insecure: bool = False
    """Skip SSL verification for self-signed certs (default: False)"""


@dataclass
class AuthResponse:
    """Response from register/login."""

    success: bool
    user_id: str
    token: str
    message: str
    token_type: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    refresh_expires_in: Optional[int] = None
    access_expires_at: Optional[str] = None
    refresh_expires_at: Optional[str] = None


@dataclass
class RecoverySetup:
    """Recovery phrase metadata returned by registration."""

    recovery_phrase: str
    recovery_words: List[str]


@dataclass
class EncryptResponse:
    """Response from file encryption."""

    status: str
    file_id: str
    file_size: int = 0
    enc_time_ms: int = 0
    upload_ms: Optional[int] = None
    read_ms: Optional[int] = None
    encrypt_ms: Optional[int] = None
    store_ms: Optional[int] = None
    total_ms: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChunkedEncryptResult:
    upload_id: str
    filename: str
    total_chunks: int
    chunk_size_bytes: int
    uploaded_chunks: int
    chunk_file_ids: List[str]
    complete: bool


@dataclass
class ResumableUploadState:
    upload_id: str
    filename: str
    file_size: int
    chunk_size_bytes: int
    total_chunks: int
    uploaded_chunks: List[int]
    chunk_file_ids: List[str]
    created_at: int
    updated_at: int


@dataclass
class ChunkedDecryptManifest:
    filename: str
    chunk_file_ids: List[str]


@dataclass
class FileInfo:
    """Info about an encrypted file."""

    file_id: str
    original_name: str
    encrypted_size: int
    created_at: str


@dataclass
class ListFilesResponse:
    """Response from listing files."""

    success: bool
    files: List[FileInfo]
    total: int


@dataclass
class DeleteResponse:
    """Response from file deletion."""

    success: bool
    message: str


@dataclass
class KeyPartResponse:
    """Response from fetching a file's key part."""

    file_id: str
    key_part_a: str
    message: str


@dataclass
class MetricsResponse:
    """Response from metrics endpoint."""

    success: bool
    total_encryptions: int
    total_decryptions: int
    total_bytes_encrypted: int
    total_bytes_decrypted: int


@dataclass
class EncryptMessagePacket:
    """E2E encrypted message packet."""

    key: str  # Encrypted AES session key (RSA encrypted)
    iv: str   # AES-GCM IV
    msg: str  # Encrypted message text (AES encrypted)


@dataclass
class GroupEncryptPacket:
    v: int
    type: str
    sender_id: str
    group_id: str
    timestamp: int
    ciphertext: str
    iv: str
    recipient_keys: Dict[str, str]


@dataclass
class PfsPreKeyBundle:
    protocol: str
    user_id: Optional[str]
    ratchet_pub_jwk: Dict[str, Any]
    created_at: int


@dataclass
class PfsMessagePacket:
    v: int
    type: str
    session_id: str
    n: int
    pn: int
    ratchet_pub_jwk: Dict[str, Any]
    iv: str
    ciphertext: str
    timestamp: int


@dataclass
class PfsSessionState:
    protocol: str
    session_id: str
    role: str
    root_key: str
    send_chain_key: str
    recv_chain_key: str
    send_count: int
    recv_count: int
    prev_send_count: int
    my_ratchet_private_jwk: Dict[str, Any]
    my_ratchet_public_jwk: Dict[str, Any]
    their_ratchet_public_jwk: Dict[str, Any]
    skipped_keys: Dict[str, str]
    created_at: int
    updated_at: int


@dataclass
class ServerEncryptResult:
    """Result from server-side message encryption."""

    encrypted_message: str
    nonce: str
    key_part_a: str
    message_tag: str
    timestamp: int


@dataclass
class ServerDecryptParams:
    """Parameters for server-side message decryption."""

    encrypted_message: str
    nonce: str
    key_part_a: str
    message_tag: Optional[str] = None


@dataclass
class ServerBatchEncryptResult:
    """Result from batch message encryption."""

    results: List[Dict[str, Any]]
    key_part_a: str
    batch_tag: str
    timestamp: int


@dataclass
class StreamSession:
    """Stream session info."""

    key_part_a: Optional[str] = None
    stream_tag: Optional[str] = None


# --- Enterprise Admin Types ---


@dataclass
class RegisterClientRequest:
    """Request to register an enterprise client."""

    client_id: str
    client_name: str
    db_type: str  # DBType
    db_config: Optional[str] = None
    api_endpoint: Optional[str] = None
    api_key: Optional[str] = None


@dataclass
class RegisterClientResponse:
    """Response from client registration."""

    status: str
    client_id: str
    wolfronix_key: str
    db_type: str
    message: str
    connector: Optional[str] = None
    api_endpoint: Optional[str] = None


@dataclass
class EnterpriseClient:
    """Enterprise client details."""

    id: int
    client_id: str
    client_name: str
    api_endpoint: str
    api_key: str
    wolfronix_key: str
    db_type: str
    db_config: str
    user_count: int
    is_active: bool
    created_at: str
    updated_at: str


@dataclass
class ListClientsResponse:
    """Response from listing clients."""

    clients: Optional[List[EnterpriseClient]]
    count: int


@dataclass
class UpdateClientRequest:
    """Request to update a client."""

    api_endpoint: Optional[str] = None
    db_type: Optional[str] = None
    db_config: Optional[str] = None


@dataclass
class UpdateClientResponse:
    """Response from client update."""

    status: str
    message: str


@dataclass
class DeactivateClientResponse:
    """Response from client deactivation."""

    status: str
    message: str
