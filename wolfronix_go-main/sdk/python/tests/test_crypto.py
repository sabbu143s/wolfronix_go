"""
Tests for Wolfronix Python SDK — Crypto module.
"""

import base64
import json

import pytest

from wolfronix.crypto import (
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


class TestKeyPairGeneration:
    """RSA-2048 key pair generation tests."""

    def test_generate_key_pair(self):
        kp = generate_key_pair()
        assert kp.public_key is not None
        assert kp.private_key is not None

    def test_export_import_public_key(self):
        kp = generate_key_pair()
        pem = export_key_to_pem(kp.public_key, "public")
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert pem.endswith("-----END PUBLIC KEY-----")

        imported = import_key_from_pem(pem, "public")
        # Re-export and compare
        pem2 = export_key_to_pem(imported, "public")
        assert pem == pem2

    def test_export_import_private_key(self):
        kp = generate_key_pair()
        pem = export_key_to_pem(kp.private_key, "private")
        assert pem.startswith("-----BEGIN PRIVATE KEY-----")

        imported = import_key_from_pem(pem, "private")
        pem2 = export_key_to_pem(imported, "private")
        assert pem == pem2


class TestKeyWrapping:
    """PBKDF2 + AES-256-GCM key wrapping tests."""

    def test_wrap_unwrap_private_key(self):
        kp = generate_key_pair()
        password = "test_password_123"

        wrapped = wrap_private_key(kp.private_key, password)
        assert wrapped.encrypted_key  # base64 string
        assert wrapped.salt  # hex string
        assert len(wrapped.salt) == 32  # 16 bytes = 32 hex chars

        # Unwrap
        unwrapped = unwrap_private_key(wrapped.encrypted_key, password, wrapped.salt)

        # Verify: export both and compare
        orig_pem = export_key_to_pem(kp.private_key, "private")
        unwrapped_pem = export_key_to_pem(unwrapped, "private")
        assert orig_pem == unwrapped_pem

    def test_wrong_password_fails(self):
        kp = generate_key_pair()
        wrapped = wrap_private_key(kp.private_key, "correct_password")

        with pytest.raises(Exception):
            unwrap_private_key(wrapped.encrypted_key, "wrong_password", wrapped.salt)


class TestAESGCM:
    """AES-256-GCM encryption tests."""

    def test_encrypt_decrypt_data(self):
        key = generate_session_key()
        plaintext = "Hello, Wolfronix!"

        encrypted, iv = encrypt_data(plaintext, key)
        assert encrypted  # base64
        assert iv  # base64

        decrypted = decrypt_data(encrypted, iv, key)
        assert decrypted == plaintext

    def test_different_key_fails(self):
        key1 = generate_session_key()
        key2 = generate_session_key()
        plaintext = "Secret message"

        encrypted, iv = encrypt_data(plaintext, key1)

        with pytest.raises(Exception):
            decrypt_data(encrypted, iv, key2)

    def test_unicode_data(self):
        key = generate_session_key()
        plaintext = "Héllo, Wörld! 你好世界 🔐"

        encrypted, iv = encrypt_data(plaintext, key)
        decrypted = decrypt_data(encrypted, iv, key)
        assert decrypted == plaintext

    def test_empty_string(self):
        key = generate_session_key()
        encrypted, iv = encrypt_data("", key)
        decrypted = decrypt_data(encrypted, iv, key)
        assert decrypted == ""

    def test_large_data(self):
        key = generate_session_key()
        plaintext = "A" * 100_000

        encrypted, iv = encrypt_data(plaintext, key)
        decrypted = decrypt_data(encrypted, iv, key)
        assert decrypted == plaintext


class TestRSA:
    """RSA-OAEP encryption tests."""

    def test_rsa_encrypt_decrypt(self):
        kp = generate_key_pair()
        data = b"Hello, RSA!"

        encrypted = rsa_encrypt(data, kp.public_key)
        assert encrypted  # base64 string

        decrypted = rsa_decrypt(encrypted, kp.private_key)
        assert decrypted == data

    def test_rsa_decrypt_base64(self):
        kp = generate_key_pair()
        data = b"Session key material"

        encrypted = rsa_encrypt(data, kp.public_key)
        result = rsa_decrypt_base64(encrypted, kp.private_key)

        # Result should be base64 of the original data
        assert base64.b64decode(result) == data

    def test_wrong_key_fails(self):
        kp1 = generate_key_pair()
        kp2 = generate_key_pair()

        encrypted = rsa_encrypt(b"secret", kp1.public_key)

        with pytest.raises(Exception):
            rsa_decrypt(encrypted, kp2.private_key)


class TestSessionKey:
    """Session key export/import tests."""

    def test_export_import_session_key(self):
        key = generate_session_key()
        exported = export_session_key(key)
        assert len(exported) == 32  # 256-bit

        imported = import_session_key(exported)
        assert imported == key

    def test_invalid_session_key_length(self):
        with pytest.raises(ValueError):
            import_session_key(b"too_short")


class TestEndToEnd:
    """End-to-end encryption flow tests (matching JS SDK behaviour)."""

    def test_full_e2e_message_flow(self):
        """Simulate the E2E chat encryption flow."""
        # Sender and recipient generate key pairs
        sender_kp = generate_key_pair()
        recipient_kp = generate_key_pair()

        # Sender encrypts a message for recipient
        session_key = generate_session_key()
        message = "Hello, Bob! This is a secret."

        # Encrypt message with session key
        encrypted_msg, iv = encrypt_data(message, session_key)

        # Encrypt session key with recipient's public key
        raw_key = export_session_key(session_key)
        encrypted_session_key = rsa_encrypt(raw_key, recipient_kp.public_key)

        # Build packet (matches JS SDK EncryptMessagePacket)
        packet = {
            "key": encrypted_session_key,
            "iv": iv,
            "msg": encrypted_msg,
        }
        packet_json = json.dumps(packet)

        # --- Recipient side ---
        received = json.loads(packet_json)

        # Decrypt session key
        raw_decrypted_key = rsa_decrypt(received["key"], recipient_kp.private_key)
        decrypted_session_key = import_session_key(raw_decrypted_key)

        # Decrypt message
        decrypted = decrypt_data(received["msg"], received["iv"], decrypted_session_key)
        assert decrypted == message

    def test_key_wrap_round_trip(self):
        """Simulate register/login key wrap flow."""
        # Registration: generate keys, wrap with password
        kp = generate_key_pair()
        pub_pem = export_key_to_pem(kp.public_key, "public")
        wrapped = wrap_private_key(kp.private_key, "user_password")

        # Simulate storing on server: encrypted_private_key, salt, public_key_pem

        # Login: fetch from server, unwrap
        recovered_private = unwrap_private_key(
            wrapped.encrypted_key, "user_password", wrapped.salt
        )
        recovered_public = import_key_from_pem(pub_pem, "public")

        # Verify recovered keys work for encryption/decryption
        test_data = b"Verify round-trip works"
        encrypted = rsa_encrypt(test_data, recovered_public)
        decrypted = rsa_decrypt(encrypted, recovered_private)
        assert decrypted == test_data
