"""
Tests for Wolfronix Python SDK — Client module.
Uses respx to mock HTTP requests.
"""

import json

import pytest
import respx
from httpx import Response

from wolfronix.client import Wolfronix
from wolfronix.crypto import export_key_to_pem, generate_key_pair, wrap_private_key
from wolfronix.errors import AuthenticationError, ValidationError, WolfronixError
from wolfronix.types import ServerDecryptParams, WolfronixConfig


@pytest.fixture
def config():
    return WolfronixConfig(
        base_url="https://wolfronix.test",
        client_id="test_client",
        wolfronix_key="test_key_123",
        insecure=True,
        timeout=5000,
        retries=1,
    )


@pytest.fixture
def wfx(config):
    return Wolfronix(config)


class TestAuthentication:
    @respx.mock
    @pytest.mark.asyncio
    async def test_register_success(self, wfx):
        respx.post("https://wolfronix.test/api/v1/keys/register").mock(
            return_value=Response(200, json={
                "success": True,
                "user_id": "user@test.com",
                "message": "User registered",
            })
        )

        result = await wfx.register("user@test.com", "password123")
        assert result.success is True
        assert result.user_id == "user@test.com"
        assert wfx.is_authenticated()
        assert wfx.has_private_key()

    @pytest.mark.asyncio
    async def test_register_empty_email(self, wfx):
        with pytest.raises(ValidationError):
            await wfx.register("", "password")

    @pytest.mark.asyncio
    async def test_register_empty_password(self, wfx):
        with pytest.raises(ValidationError):
            await wfx.register("user@test.com", "")

    @respx.mock
    @pytest.mark.asyncio
    async def test_login_success(self, wfx):
        # Generate keys and wrap them to simulate server response
        kp = generate_key_pair()
        pub_pem = export_key_to_pem(kp.public_key, "public")
        wrapped = wrap_private_key(kp.private_key, "password123")

        respx.post("https://wolfronix.test/api/v1/keys/login").mock(
            return_value=Response(200, json={
                "encrypted_private_key": wrapped.encrypted_key,
                "salt": wrapped.salt,
                "public_key_pem": pub_pem,
            })
        )

        result = await wfx.login("user@test.com", "password123")
        assert result.success is True
        assert wfx.is_authenticated()
        assert wfx.has_private_key()

    @respx.mock
    @pytest.mark.asyncio
    async def test_login_wrong_password(self, wfx):
        kp = generate_key_pair()
        pub_pem = export_key_to_pem(kp.public_key, "public")
        wrapped = wrap_private_key(kp.private_key, "correct_password")

        respx.post("https://wolfronix.test/api/v1/keys/login").mock(
            return_value=Response(200, json={
                "encrypted_private_key": wrapped.encrypted_key,
                "salt": wrapped.salt,
                "public_key_pem": pub_pem,
            })
        )

        with pytest.raises(AuthenticationError, match="decryption failed"):
            await wfx.login("user@test.com", "wrong_password")

    def test_logout(self, wfx):
        wfx.set_token("test-token", "user@test.com")
        assert wfx.is_authenticated()

        wfx.logout()
        assert not wfx.is_authenticated()
        assert not wfx.has_private_key()

    def test_set_token(self, wfx):
        wfx.set_token("my-token", "user@test.com")
        assert wfx.is_authenticated()
        assert wfx.get_user_id() == "user@test.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_recover_account_success(self, wfx):
        kp = generate_key_pair()
        pub_pem = export_key_to_pem(kp.public_key, "public")
        recovery_wrap = wrap_private_key(kp.private_key, "alpha beta gamma")
        new_wrap = wrap_private_key(kp.private_key, "new_password")

        respx.post("https://wolfronix.test/api/v1/keys/recover").mock(
            return_value=Response(200, json={
                "recovery_encrypted_private_key": recovery_wrap.encrypted_key,
                "recovery_salt": recovery_wrap.salt,
                "public_key_pem": pub_pem,
            })
        )
        respx.post("https://wolfronix.test/api/v1/keys/update-password").mock(
            return_value=Response(200, json={"status": "success"})
        )

        result = await wfx.recover_account("user@test.com", "alpha beta gamma", "new_password")
        assert result.success is True
        assert wfx.is_authenticated()
        assert wfx.has_private_key()

    @respx.mock
    @pytest.mark.asyncio
    async def test_login_completes_auth_challenge(self, wfx):
        kp = generate_key_pair()
        pub_pem = export_key_to_pem(kp.public_key, "public")
        wrapped = wrap_private_key(kp.private_key, "password123")

        respx.post("https://wolfronix.test/api/v1/keys/login").mock(
            return_value=Response(200, json={
                "encrypted_private_key": wrapped.encrypted_key,
                "salt": wrapped.salt,
                "public_key_pem": pub_pem,
                "auth_challenge_id": "challenge-1",
                "auth_challenge_payload": "payload-1",
            })
        )
        respx.post("https://wolfronix.test/api/v1/auth/complete-login").mock(
            return_value=Response(200, json={
                "status": "success",
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "expires_in": 900,
                "refresh_expires_in": 3600,
            })
        )

        result = await wfx.login("user@test.com", "password123")
        assert result.success is True
        assert result.access_token == "access-1"
        assert wfx.is_authenticated()

    @pytest.mark.asyncio
    async def test_rotate_identity_keys_not_supported(self, wfx):
        wfx.set_token("token", "user@test.com")
        with pytest.raises(WolfronixError) as exc:
            await wfx.rotate_identity_keys("password123")
        assert exc.value.code == "NOT_SUPPORTED"


class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self, wfx):
        respx.get("https://wolfronix.test/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        assert await wfx.health_check() is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure(self, wfx):
        respx.get("https://wolfronix.test/health").mock(
            return_value=Response(500, json={"status": "error"})
        )
        assert await wfx.health_check() is False


class TestFileOperations:
    @respx.mock
    @pytest.mark.asyncio
    async def test_list_files(self, wfx):
        wfx.set_token("token", "user@test.com")
        respx.get("https://wolfronix.test/api/v1/files").mock(
            return_value=Response(200, json=[
                {"id": "1", "name": "test.pdf", "size_bytes": 1024, "date": "2025-01-01"},
                {"id": "2", "name": "doc.txt", "size_bytes": 256, "date": "2025-01-02"},
            ])
        )

        result = await wfx.list_files()
        assert result.success is True
        assert result.total == 2
        assert result.files[0].file_id == "1"
        assert result.files[0].original_name == "test.pdf"

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_file(self, wfx):
        wfx.set_token("token", "user@test.com")
        respx.delete("https://wolfronix.test/api/v1/files/123").mock(
            return_value=Response(200, json={"success": True, "message": "Deleted"})
        )

        result = await wfx.delete_file("123")
        assert result.success is True

    @pytest.mark.asyncio
    async def test_delete_file_empty_id(self, wfx):
        wfx.set_token("token", "user@test.com")
        with pytest.raises(ValidationError):
            await wfx.delete_file("")

    @pytest.mark.asyncio
    async def test_encrypt_resumable_invalid_chunk_size(self, wfx):
        wfx.set_token("token", "user@test.com")
        with pytest.raises(ValidationError):
            await wfx.encrypt_resumable(b"hello", chunk_size_bytes=1024)


class TestServerEncryption:
    @respx.mock
    @pytest.mark.asyncio
    async def test_server_encrypt(self, wfx):
        wfx.set_token("token", "user@test.com")
        respx.post("https://wolfronix.test/api/v1/messages/encrypt").mock(
            return_value=Response(200, json={
                "encrypted_message": "enc_msg_b64",
                "nonce": "nonce_b64",
                "key_part_a": "key_a_b64",
                "message_tag": "tag123",
                "timestamp": 1700000000,
            })
        )

        result = await wfx.server_encrypt("Hello!")
        assert result.encrypted_message == "enc_msg_b64"
        assert result.key_part_a == "key_a_b64"
        assert result.message_tag == "tag123"

    @respx.mock
    @pytest.mark.asyncio
    async def test_server_decrypt(self, wfx):
        wfx.set_token("token", "user@test.com")
        respx.post("https://wolfronix.test/api/v1/messages/decrypt").mock(
            return_value=Response(200, json={
                "message": "Decrypted text",
                "timestamp": 1700000000,
            })
        )

        result = await wfx.server_decrypt(ServerDecryptParams(
            encrypted_message="enc",
            nonce="nonce",
            key_part_a="key_a",
            message_tag="tag",
        ))
        assert result == "Decrypted text"

    @respx.mock
    @pytest.mark.asyncio
    async def test_server_encrypt_batch(self, wfx):
        wfx.set_token("token", "user@test.com")
        respx.post("https://wolfronix.test/api/v1/messages/batch/encrypt").mock(
            return_value=Response(200, json={
                "results": [
                    {"id": "m1", "encrypted_message": "e1", "nonce": "n1", "seq": 0},
                    {"id": "m2", "encrypted_message": "e2", "nonce": "n2", "seq": 1},
                ],
                "key_part_a": "shared_key",
                "batch_tag": "batch_tag",
                "timestamp": 1700000000,
            })
        )

        result = await wfx.server_encrypt_batch([
            {"id": "m1", "message": "Hello"},
            {"id": "m2", "message": "World"},
        ])
        assert len(result.results) == 2
        assert result.key_part_a == "shared_key"


class TestMetrics:
    @respx.mock
    @pytest.mark.asyncio
    async def test_get_metrics(self, wfx):
        wfx.set_token("token", "user@test.com")
        respx.get("https://wolfronix.test/api/v1/metrics/summary").mock(
            return_value=Response(200, json={
                "success": True,
                "total_encryptions": 100,
                "total_decryptions": 50,
                "total_bytes_encrypted": 1024000,
                "total_bytes_decrypted": 512000,
            })
        )

        metrics = await wfx.get_metrics()
        assert metrics.success is True
        assert metrics.total_encryptions == 100
        assert metrics.total_decryptions == 50
