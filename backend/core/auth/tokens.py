"""Refresh-token persistence, rotation and revocation.

Access tokens stay stateless and short-lived. Refresh tokens are stored by
``jti`` so they can be rotated, revoked on logout, and detected when an old
token is replayed (reuse detection revokes the whole login family).
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import pymysql
from fastapi import HTTPException, status
from jose import JWTError, jwt

from config import settings
from core.auth.jwt import ALGORITHM, SECRET_KEY, create_access_token


def _connect():
    return pymysql.connect(
        host=settings.MYSQL_HOST,
        user=settings.MYSQL_USER,
        password=settings.MYSQL_PASSWORD,
        database=settings.MYSQL_DB,
        port=settings.MYSQL_PORT,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _encode_refresh(user_id: int, jti: str, family_id: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode(
        {
            "sub": str(user_id),
            "typ": "refresh",
            "jti": jti,
            "fam": family_id,
            "exp": expires,
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def _insert(cursor, jti: str, family_id: str, user_id: int, expires_at: datetime, user_agent: str) -> None:
    cursor.execute(
        """INSERT INTO refresh_tokens (jti, family_id, user_id, expires_at, user_agent)
           VALUES (%s, %s, %s, %s, %s)""",
        (jti, family_id, user_id, expires_at, (user_agent or "")[:255]),
    )


def issue_session(user_id: int, username: str, user_agent: str = "") -> Tuple[str, str]:
    """Create a new login family and return (access_token, refresh_token)."""
    family_id = secrets.token_hex(16)
    jti = secrets.token_hex(16)
    expires_at = _utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    conn = _connect()
    try:
        with conn.cursor() as cursor:
            _insert(cursor, jti, family_id, user_id, expires_at, user_agent)
        conn.commit()
    finally:
        conn.close()
    return create_access_token(data={"sub": username, "uid": user_id}), _encode_refresh(user_id, jti, family_id)


def rotate(refresh_token: str, user_agent: str = "") -> Tuple[str, str, Dict[str, Any]]:
    """Rotate a refresh token. Raises 401 on invalid/expired/replayed tokens."""
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as error:
        raise _unauthorized("Refresh token 无效或已过期") from error
    if payload.get("typ") != "refresh":
        raise _unauthorized("Refresh token 类型不正确")

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as error:
        raise _unauthorized("Refresh token 载荷不完整") from error
    jti = str(payload.get("jti") or "")
    family_id = str(payload.get("fam") or "")
    if not jti or not family_id:
        raise _unauthorized("Refresh token 载荷不完整")

    conn = _connect()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT jti, family_id, user_id, expires_at, revoked_at, replaced_by
                   FROM refresh_tokens WHERE jti=%s FOR UPDATE""",
                (jti,),
            )
            row = cursor.fetchone()
            if row is None:
                raise _unauthorized("Refresh token 不存在")

            # Replay of a rotated token: revoke the whole family.
            if row["revoked_at"] is not None:
                if row["replaced_by"]:
                    cursor.execute(
                        "UPDATE refresh_tokens SET revoked_at=%s "
                        "WHERE family_id=%s AND revoked_at IS NULL",
                        (_utcnow(), family_id),
                    )
                    conn.commit()
                    # A replayed refresh token is a strong signal of theft:
                    # also invalidate access tokens issued for this user.
                    from core import state

                    state.revoke_user_access(
                        user_id, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
                    )
                raise _unauthorized("Refresh token 已失效，请重新登录")

            if row["expires_at"] <= _utcnow():
                cursor.execute(
                    "UPDATE refresh_tokens SET revoked_at=%s WHERE jti=%s",
                    (_utcnow(), jti),
                )
                conn.commit()
                raise _unauthorized("Refresh token 已过期，请重新登录")

            cursor.execute(
                "SELECT id, username, role, email, full_name, is_active FROM users WHERE id=%s",
                (user_id,),
            )
            user = cursor.fetchone()
            if not user or not user.get("is_active"):
                raise _unauthorized("账号不存在或已停用")

            new_jti = secrets.token_hex(16)
            new_expires = _utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            updated = cursor.execute(
                "UPDATE refresh_tokens SET revoked_at=%s, replaced_by=%s "
                "WHERE jti=%s AND revoked_at IS NULL",
                (_utcnow(), new_jti, jti),
            )
            if updated != 1:
                conn.rollback()
                raise _unauthorized("Refresh token 已被使用，请重新登录")

            _insert(cursor, new_jti, family_id, user_id, new_expires, user_agent)
        conn.commit()
    finally:
        conn.close()

    access = create_access_token(data={"sub": user["username"], "uid": user_id})
    return access, _encode_refresh(user_id, new_jti, family_id), user


def revoke(refresh_token: str) -> None:
    """Revoke one refresh token; unknown/invalid tokens are ignored."""
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return
    jti = payload.get("jti")
    if not jti:
        return
    conn = _connect()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE refresh_tokens SET revoked_at=%s WHERE jti=%s AND revoked_at IS NULL",
                (_utcnow(), jti),
            )
        conn.commit()
    finally:
        conn.close()


def revoke_all(user_id: int) -> int:
    conn = _connect()
    try:
        with conn.cursor() as cursor:
            count = cursor.execute(
                "UPDATE refresh_tokens SET revoked_at=%s WHERE user_id=%s AND revoked_at IS NULL",
                (_utcnow(), user_id),
            )
        conn.commit()
        return int(count)
    finally:
        conn.close()


def revoke_access(token: Optional[str]) -> None:
    """Revoke the access token presented to /api/auth/logout (jti denylist)."""
    if not token:
        return
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return
    if payload.get("typ", "access") != "access":
        return
    exp = payload.get("exp")
    ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1) if exp else 900
    from core import state

    state.revoke_access_token(payload.get("jti"), ttl)


def revoke_all_access(user_id: int) -> None:
    from core import state

    state.revoke_user_access(user_id, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
