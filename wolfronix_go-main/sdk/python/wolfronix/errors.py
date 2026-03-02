"""
Custom exception classes for Wolfronix SDK.
Mirrors the TypeScript SDK error hierarchy.
"""

from __future__ import annotations
from typing import Any, Dict, Optional


class WolfronixError(Exception):
    """Base error class for all Wolfronix SDK errors."""

    def __init__(
        self,
        message: str = "An error occurred",
        code: str = "WOLFRONIX_ERROR",
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class AuthenticationError(WolfronixError):
    """Raised when authentication fails (401)."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, "AUTH_ERROR", 401)


class FileNotFoundError(WolfronixError):
    """Raised when a file is not found (404)."""

    def __init__(self, file_id: str = ""):
        super().__init__(f"File not found: {file_id}", "FILE_NOT_FOUND", 404)


class PermissionDeniedError(WolfronixError):
    """Raised when permission is denied (403)."""

    def __init__(self, message: str = "Permission denied"):
        super().__init__(message, "PERMISSION_DENIED", 403)


class NetworkError(WolfronixError):
    """Raised on network/connection failures."""

    def __init__(self, message: str = "Network request failed"):
        super().__init__(message, "NETWORK_ERROR")


class ValidationError(WolfronixError):
    """Raised when input validation fails (400)."""

    def __init__(self, message: str = "Validation error"):
        super().__init__(message, "VALIDATION_ERROR", 400)
