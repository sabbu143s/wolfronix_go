"""
Wolfronix SDK for Python
Zero-knowledge encryption made simple

@package wolfronix-sdk
@version 1.0.0
"""

from .client import Wolfronix, create_client
from .admin import WolfronixAdmin
from .crypto import (
    generate_key_pair,
    export_key_to_pem,
    import_key_from_pem,
    wrap_private_key,
    unwrap_private_key,
    generate_session_key,
    encrypt_data,
    decrypt_data,
    rsa_encrypt,
    rsa_decrypt,
    rsa_decrypt_base64,
    export_session_key,
    import_session_key,
)
from .errors import (
    WolfronixError,
    AuthenticationError,
    FileNotFoundError as WolfronixFileNotFoundError,
    PermissionDeniedError,
    NetworkError,
    ValidationError,
)
from .types import (
    WolfronixConfig,
    WolfronixAdminConfig,
    AuthResponse,
    EncryptResponse,
    FileInfo,
    ListFilesResponse,
    DeleteResponse,
    KeyPartResponse,
    MetricsResponse,
    EncryptMessagePacket,
    ServerEncryptResult,
    ServerDecryptParams,
    ServerBatchEncryptResult,
    StreamSession,
    RegisterClientRequest,
    RegisterClientResponse,
    ListClientsResponse,
    EnterpriseClient,
    UpdateClientRequest,
    UpdateClientResponse,
    DeactivateClientResponse,
    DBType,
)

__version__ = "1.0.0"
__all__ = [
    # Main clients
    "Wolfronix",
    "WolfronixAdmin",
    "create_client",
    # Crypto
    "generate_key_pair",
    "export_key_to_pem",
    "import_key_from_pem",
    "wrap_private_key",
    "unwrap_private_key",
    "generate_session_key",
    "encrypt_data",
    "decrypt_data",
    "rsa_encrypt",
    "rsa_decrypt",
    "rsa_decrypt_base64",
    "export_session_key",
    "import_session_key",
    # Errors
    "WolfronixError",
    "AuthenticationError",
    "WolfronixFileNotFoundError",
    "PermissionDeniedError",
    "NetworkError",
    "ValidationError",
    # Types
    "WolfronixConfig",
    "WolfronixAdminConfig",
    "AuthResponse",
    "EncryptResponse",
    "FileInfo",
    "ListFilesResponse",
    "DeleteResponse",
    "KeyPartResponse",
    "MetricsResponse",
    "EncryptMessagePacket",
    "ServerEncryptResult",
    "ServerDecryptParams",
    "ServerBatchEncryptResult",
    "StreamSession",
    "RegisterClientRequest",
    "RegisterClientResponse",
    "ListClientsResponse",
    "EnterpriseClient",
    "UpdateClientRequest",
    "UpdateClientResponse",
    "DeactivateClientResponse",
    "DBType",
]
