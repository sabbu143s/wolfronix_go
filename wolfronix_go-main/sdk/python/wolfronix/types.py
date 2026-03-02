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
