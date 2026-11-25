"""Persistent audit trail for privileged/security-relevant actions."""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger("sec_llm.audit")


def record(
    db,
    *,
    user_id: Optional[int],
    username: str,
    action: str,
    target: str = "",
    detail: Optional[dict[str, Any]] = None,
    request=None,
) -> None:
    """Insert an audit row; never fail the caller's request."""
    ip = ""
    try:
        if request is not None and request.client is not None:
            ip = (request.client.host or "")[:64]
    except Exception:  # noqa: BLE001
        ip = ""
    try:
        with db.cursor() as cursor:
            cursor.execute(
                """INSERT INTO audit_events (user_id, username, action, target, detail, ip)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    user_id,
                    (username or "")[:50],
                    (action or "")[:50],
                    (target or "")[:500],
                    json.dumps(detail or {}, ensure_ascii=False),
                    ip,
                ),
            )
    except Exception as error:  # noqa: BLE001 —— 审计失败不应阻断业务
        logger.warning("audit write failed: %s", error)
