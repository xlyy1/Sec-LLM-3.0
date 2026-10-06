"""Tests for the auth module."""
import pytest
from core.auth.password import verify_password, get_password_hash
from core.auth.jwt import create_access_token, get_current_user


class TestPasswordHashing:
    def test_hash_and_verify(self):
        pw = "test-password-123"
        hashed = get_password_hash(pw)
        assert hashed != pw
        assert verify_password(pw, hashed)
        assert not verify_password("wrong-password", hashed)

    def test_different_hashes(self):
        h1 = get_password_hash("pw1")
        h2 = get_password_hash("pw1")
        assert h1 != h2
        assert verify_password("pw1", h1)
        assert verify_password("pw1", h2)


class TestJwt:
    def test_create_token(self):
        token = create_access_token({"sub": "testuser"})
        assert token is not None
        assert len(token) > 50

    def test_token_with_expiry(self):
        from datetime import timedelta
        token = create_access_token({"sub": "testuser"}, expires_delta=timedelta(hours=1))
        assert token is not None

    def test_disabled_user_token_is_rejected(self):
        import asyncio

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def execute(self, *_):
                pass

            def fetchone(self):
                return {"username": "disabled", "is_active": False}

        class DB:
            def cursor(self):
                return Cursor()

        token = create_access_token({"sub": "disabled"})
        assert asyncio.run(get_current_user(token, DB())) is None
