"""JWT token creation and user extraction."""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from config import settings

SECRET_KEY = settings.JWT_SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    token_type: str = "access",
) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # jti/iat let logout and "revoke all sessions" invalidate live access tokens
    # instead of waiting for the 15 minute expiry.
    to_encode.update(
        {
            "exp": expire,
            "iat": now.timestamp(),
            "jti": secrets.token_hex(16),
            "typ": token_type,
        }
    )
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db=None,
) -> Optional[Dict[str, Any]]:
    """Decode JWT token and fetch user from DB. db is injected as Depends(get_db)."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Verification emails are signed with the same key; only access tokens may
        # authenticate a session. Tokens issued before this claim existed carry no
        # "typ" and stay valid as access tokens.
        if payload.get("typ", "access") != "access":
            return None
        username: str = payload.get("sub")
        if username is None:
            return None
    except JWTError:
        return None

    from core import state

    if state.access_token_revoked(
        payload.get("jti"), payload.get("uid"), payload.get("iat")
    ):
        return None

    if db is None:
        return None
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        return user if user and user.get("is_active") else None
