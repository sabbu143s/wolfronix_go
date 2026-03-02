"""
Cryptographic utilities for client-side key management.
Uses the `cryptography` library — mirrors the TypeScript SDK's Web Crypto API usage.

Algorithms:
  - RSA-OAEP 2048-bit (SHA-256) for asymmetric encryption
  - AES-256-GCM for symmetric encryption
  - PBKDF2 (100 000 iterations, SHA-256) for password-based key derivation
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Constants ────────────────────────────────────────────────────────────────

RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
PBKDF2_ITERATIONS = 100_000
AES_KEY_LENGTH = 32  # 256-bit
GCM_IV_LENGTH = 12   # 96-bit nonce
SALT_LENGTH = 16     # 128-bit salt


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class KeyPair:
    """RSA key pair container."""
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey


@dataclass
class WrappedKey:
    """Wrapped (encrypted) private key + salt."""
    encrypted_key: str   # Base64-encoded (IV + ciphertext)
    salt: str            # Hex-encoded salt


# ── RSA Key Pair ─────────────────────────────────────────────────────────────

def generate_key_pair() -> KeyPair:
    """Generate a new RSA-2048 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return KeyPair(
        public_key=private_key.public_key(),
        private_key=private_key,
    )


def export_key_to_pem(key: object, key_type: str) -> str:
    """
    Export an RSA key to PEM format.

    Args:
        key: RSA public or private key object.
        key_type: ``"public"`` or ``"private"``.

    Returns:
        PEM-encoded string.
    """
    if key_type == "public":
        pem_bytes = key.public_bytes(  # type: ignore[union-attr]
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        pem_bytes = key.private_bytes(  # type: ignore[union-attr]
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    return pem_bytes.decode("utf-8").strip()


def import_key_from_pem(pem: str, key_type: str):
    """
    Import an RSA key from PEM format.

    Args:
        pem: PEM-encoded key string.
        key_type: ``"public"`` or ``"private"``.

    Returns:
        RSA key object.
    """
    pem_bytes = pem.encode("utf-8")
    if key_type == "public":
        return serialization.load_pem_public_key(pem_bytes)
    else:
        return serialization.load_pem_private_key(pem_bytes, password=None)


# ── Password-Based Key Wrapping (PBKDF2 + AES-256-GCM) ──────────────────────

def _derive_wrapping_key(password: str, salt_hex: str) -> bytes:
    """Derive a 256-bit AES key from a password and hex-encoded salt using PBKDF2."""
    salt = bytes.fromhex(salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def wrap_private_key(private_key: rsa.RSAPrivateKey, password: str) -> WrappedKey:
    """
    Wrap (encrypt) a private key with a password-derived key.

    Matches the TypeScript SDK behaviour:
      1. Generate random 16-byte salt
      2. Derive AES-256 key via PBKDF2
      3. Export private key to PKCS8 DER
      4. Encrypt with AES-256-GCM (random 12-byte IV)
      5. Return ``base64(IV + ciphertext + tag)`` and hex salt

    Returns:
        WrappedKey with ``encrypted_key`` (base64) and ``salt`` (hex).
    """
    # Generate salt
    salt = os.urandom(SALT_LENGTH)
    salt_hex = salt.hex()

    # Derive wrapping key
    wrapping_key = _derive_wrapping_key(password, salt_hex)

    # Export private key as PKCS8 DER
    key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Encrypt with AES-256-GCM
    iv = os.urandom(GCM_IV_LENGTH)
    aesgcm = AESGCM(wrapping_key)
    ciphertext = aesgcm.encrypt(iv, key_der, None)  # ciphertext includes tag

    # Combine: IV (12 bytes) + ciphertext+tag
    combined = iv + ciphertext
    encrypted_key_b64 = base64.b64encode(combined).decode("utf-8")

    return WrappedKey(encrypted_key=encrypted_key_b64, salt=salt_hex)


def unwrap_private_key(
    encrypted_key_b64: str, password: str, salt_hex: str
) -> rsa.RSAPrivateKey:
    """
    Unwrap (decrypt) a private key with a password-derived key.

    Matches the TypeScript SDK:
      1. base64-decode to get IV (first 12 bytes) + ciphertext+tag
      2. Derive AES key from password + salt via PBKDF2
      3. Decrypt with AES-256-GCM
      4. Import the resulting PKCS8 DER as an RSA private key

    Raises:
        Exception: If the password is wrong (decryption fails).
    """
    combined = base64.b64decode(encrypted_key_b64)
    iv = combined[:GCM_IV_LENGTH]
    ciphertext = combined[GCM_IV_LENGTH:]

    wrapping_key = _derive_wrapping_key(password, salt_hex)

    aesgcm = AESGCM(wrapping_key)
    key_der = aesgcm.decrypt(iv, ciphertext, None)

    return serialization.load_der_private_key(key_der, password=None)  # type: ignore[return-value]


# ── Hybrid Encryption Primitives (for E2E Chat) ─────────────────────────────

def generate_session_key() -> bytes:
    """Generate a random 256-bit AES-GCM session key (raw bytes)."""
    return os.urandom(AES_KEY_LENGTH)


def encrypt_data(data: str, key: bytes) -> Tuple[str, str]:
    """
    Encrypt a string with AES-256-GCM.

    Args:
        data: Plaintext string to encrypt.
        key: 32-byte AES key.

    Returns:
        Tuple of ``(encrypted_b64, iv_b64)``.
    """
    iv = os.urandom(GCM_IV_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data.encode("utf-8"), None)

    return (
        base64.b64encode(ciphertext).decode("utf-8"),
        base64.b64encode(iv).decode("utf-8"),
    )


def decrypt_data(encrypted_b64: str, iv_b64: str, key: bytes) -> str:
    """
    Decrypt AES-256-GCM encrypted data.

    Args:
        encrypted_b64: Base64-encoded ciphertext (includes GCM tag).
        iv_b64: Base64-encoded IV.
        key: 32-byte AES key.

    Returns:
        Decrypted plaintext string.
    """
    ciphertext = base64.b64decode(encrypted_b64)
    iv = base64.b64decode(iv_b64)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


def rsa_encrypt(data: bytes, public_key: rsa.RSAPublicKey) -> str:
    """
    Encrypt data with RSA-OAEP (SHA-256).

    Returns:
        Base64-encoded ciphertext.
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt(encrypted_b64: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypt RSA-OAEP (SHA-256) ciphertext.

    Args:
        encrypted_b64: Base64-encoded ciphertext.
        private_key: RSA private key.

    Returns:
        Decrypted raw bytes.
    """
    ciphertext = base64.b64decode(encrypted_b64)
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_base64(encrypted_b64: str, private_key: rsa.RSAPrivateKey) -> str:
    """
    Decrypt RSA-OAEP ciphertext and return plaintext as base64.
    Used for client-side decryption of key_part_a in the zero-knowledge decrypt flow.
    """
    decrypted = rsa_decrypt(encrypted_b64, private_key)
    return base64.b64encode(decrypted).decode("utf-8")


def export_session_key(key: bytes) -> bytes:
    """Export raw session key bytes (identity — included for API parity with TS SDK)."""
    return key


def import_session_key(raw: bytes) -> bytes:
    """Import raw session key bytes (identity — included for API parity with TS SDK)."""
    if len(raw) != AES_KEY_LENGTH:
        raise ValueError(f"Session key must be {AES_KEY_LENGTH} bytes, got {len(raw)}")
    return raw
