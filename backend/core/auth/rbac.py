"""Role helpers shared by the API and Agent endpoints.

Roles:
  admin    — everything, including user management
  operator — run scans, chat, upload, cancel own tasks
  viewer   — read-only (history, reports, status)

Legacy accounts with role "user" are treated as operator so existing
deployments keep working until an admin assigns an explicit role.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import HTTPException, status

ROLE_ALIASES = {"user": "operator"}
VALID_ROLES = ("admin", "operator", "viewer")
_WRITE_ROLES = {"admin", "operator"}


def normalize_role(role: Any) -> str:
    value = str(role or "").strip().lower() or "viewer"
    return ROLE_ALIASES.get(value, value)


def is_admin(user: Dict[str, Any]) -> bool:
    return normalize_role(user.get("role")) == "admin"


def can_write(user: Dict[str, Any]) -> bool:
    return normalize_role(user.get("role")) in _WRITE_ROLES


def require_write(user: Dict[str, Any]) -> None:
    if not can_write(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="当前角色为只读（viewer），无法执行该操作",
        )
