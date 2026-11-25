"""Shared runtime state.

Login throttling is the first piece that must survive multiple API workers:
the counter lives in Redis when REDIS_URL is configured, and falls back to a
bounded in-process window when Redis is absent or unreachable. The fallback
keeps single-node deployments working without an extra dependency.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

logger = logging.getLogger("sec_llm.state")

_KEY_PREFIX = "sec-llm:login:"
_MEMORY_MAX_KEYS = 10_000

_redis = None
_redis_retry_after = 0.0
_memory: Dict[str, Deque[float]] = defaultdict(deque)
_memory_lock = threading.Lock()


def _settings():
    from config import settings

    return settings


def redis_url() -> str:
    return (getattr(_settings(), "REDIS_URL", "") or "").strip()


def _client():
    """Return a live Redis client, or None when Redis is not configured/down."""
    global _redis, _redis_retry_after
    if _redis is not None:
        return _redis
    if time.monotonic() < _redis_retry_after:
        return None
    url = redis_url()
    if not url:
        _redis_retry_after = time.monotonic() + 300
        return None
    try:
        import redis

        client = redis.Redis.from_url(
            url,
            socket_connect_timeout=1,
            socket_timeout=1,
            decode_responses=True,
        )
        client.ping()
    except Exception as error:  # noqa: BLE001 —— 降级而不是让登录接口失败
        _redis_retry_after = time.monotonic() + 30
        logger.warning("redis unavailable, using in-process login throttle: %s", error)
        return None
    _redis = client
    logger.info("redis connected for shared login throttle")
    return client


def _mark_redis_down() -> None:
    global _redis, _redis_retry_after
    _redis = None
    _redis_retry_after = time.monotonic() + 30


def _key(key: str) -> str:
    return _KEY_PREFIX + key


def login_blocked(key: str, limit: int, window: int) -> bool:
    client = _client()
    if client is not None:
        try:
            return int(client.get(_key(key)) or 0) >= limit
        except Exception:  # noqa: BLE001
            _mark_redis_down()
    now = time.time()
    with _memory_lock:
        attempts = _memory[key]
        while attempts and now - attempts[0] > window:
            attempts.popleft()
        return len(attempts) >= limit


def record_login_failure(key: str, window: int) -> None:
    client = _client()
    if client is not None:
        try:
            pipe = client.pipeline()
            pipe.incr(_key(key))
            # nx keeps the original window for the first failure instead of
            # sliding it on every retry (same semantics as the deque fallback).
            pipe.expire(_key(key), window, nx=True)
            pipe.execute()
            return
        except Exception:  # noqa: BLE001
            _mark_redis_down()

    now = time.time()
    with _memory_lock:
        _memory[key].append(now)
        if len(_memory) > _MEMORY_MAX_KEYS:
            cutoff = now - window
            for stale in [k for k, v in _memory.items() if not v or v[-1] < cutoff]:
                _memory.pop(stale, None)


def clear_login_failures(key: str) -> None:
    client = _client()
    if client is not None:
        try:
            client.delete(_key(key))
        except Exception:  # noqa: BLE001
            _mark_redis_down()
    with _memory_lock:
        _memory.pop(key, None)


def redis_status() -> str:
    """'disabled' | 'ok' | 'unavailable' — for /readyz reporting."""
    if not redis_url():
        return "disabled"
    client = _client()
    if client is None:
        return "unavailable"
    try:
        client.ping()
        return "ok"
    except Exception:  # noqa: BLE001
        _mark_redis_down()
        return "unavailable"


_quota_memory: Dict[str, int] = {}


def add_token_usage(
    user_id: Any, model: str, prompt_tokens: int, completion_tokens: int
) -> None:
    """Aggregate LLM token usage per user per UTC day."""
    prompt = max(int(prompt_tokens or 0), 0)
    completion = max(int(completion_tokens or 0), 0)
    if not prompt and not completion:
        return
    day = time.strftime("%Y%m%d", time.gmtime())
    key = f"sec-llm:usage:{user_id}:{day}"
    client = _client()
    if client is not None:
        try:
            pipe = client.pipeline()
            pipe.hincrby(key, "prompt", prompt)
            pipe.hincrby(key, "completion", completion)
            pipe.hincrby(key, "requests", 1)
            pipe.expire(key, 172800, nx=True)
            pipe.execute()
            return
        except Exception:  # noqa: BLE001
            _mark_redis_down()

    with _memory_lock:
        bucket = _usage_memory.setdefault(key, {})
        bucket["prompt"] = bucket.get("prompt", 0) + prompt
        bucket["completion"] = bucket.get("completion", 0) + completion
        bucket["requests"] = bucket.get("requests", 0) + 1


_usage_memory: Dict[str, Dict[str, int]] = {}


def usage_today(user_id: Any) -> Dict[str, Any]:
    """Return today's token totals and an optional USD estimate."""
    day = time.strftime("%Y%m%d", time.gmtime())
    key = f"sec-llm:usage:{user_id}:{day}"
    values = {"prompt": 0, "completion": 0, "requests": 0}

    client = _client()
    if client is not None:
        try:
            raw = client.hgetall(key) or {}
            values = {k: int(raw.get(k, 0)) for k in values}
        except Exception:  # noqa: BLE001
            _mark_redis_down()
            with _memory_lock:
                values = dict(_usage_memory.get(key, values))
    else:
        with _memory_lock:
            values = dict(_usage_memory.get(key, values))

    settings = _settings()
    prompt_cost = values["prompt"] / 1000 * float(getattr(settings, "LLM_COST_PER_1K_PROMPT", 0.0))
    completion_cost = values["completion"] / 1000 * float(
        getattr(settings, "LLM_COST_PER_1K_COMPLETION", 0.0)
    )
    return {
        "day": day,
        "prompt_tokens": values["prompt"],
        "completion_tokens": values["completion"],
        "total_tokens": values["prompt"] + values["completion"],
        "requests": values["requests"],
        "estimated_cost_usd": round(prompt_cost + completion_cost, 6),
    }


def token_budget_exceeded(user_id: Any, limit: int) -> bool:
    if limit <= 0:
        return False
    return usage_today(user_id)["total_tokens"] >= limit


# --- Cluster-wide Agent concurrency and session events ---
_AGENT_SLOT_KEY = "sec-llm:agent:slots"
_SLOT_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - ttl)
if redis.call('ZCARD', key) >= limit then
  return 0
end
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, ttl * 1000)
return 1
"""


def publish_session_event(session_id: str) -> None:
    """Wake SSE subscribers on any worker via Redis Pub/Sub."""
    client = _client()
    if client is None:
        return
    try:
        client.publish(f"sec-llm:session:{session_id}", "1")
    except Exception:  # noqa: BLE001
        _mark_redis_down()


def acquire_agent_slot(session_id: str, limit: int, ttl_seconds: int) -> bool:
    """One attempt at a cluster-wide Agent slot.

    Returns True when Redis is disabled/unavailable so single-node behaviour
    falls back to the in-process semaphore.
    """
    if limit <= 0:
        return True
    client = _client()
    if client is None:
        return True
    try:
        return bool(
            client.eval(
                _SLOT_LUA,
                1,
                _AGENT_SLOT_KEY,
                time.time(),
                max(int(ttl_seconds), 60),
                int(limit),
                session_id,
            )
        )
    except Exception:  # noqa: BLE001
        _mark_redis_down()
        return True


def release_agent_slot(session_id: str) -> None:
    client = _client()
    if client is None:
        return
    try:
        client.zrem(_AGENT_SLOT_KEY, session_id)
    except Exception:  # noqa: BLE001
        _mark_redis_down()


def wait_for_agent_slot(
    session_id: str, limit: int, ttl_seconds: int, timeout_seconds: float
) -> bool:
    deadline = time.time() + max(timeout_seconds, 1)
    while time.time() < deadline:
        if acquire_agent_slot(session_id, limit, ttl_seconds):
            return True
        time.sleep(2)
    return False


def consume_quota(user_id: int, kind: str, limit: int) -> tuple[bool, int]:
    """Count one request against the user's daily quota.

    Returns (allowed, used). limit <= 0 means unlimited. Redis is preferred so
    all workers share the counter; without it the fallback is per-process.
    """
    if limit <= 0:
        return True, 0
    day = time.strftime("%Y%m%d", time.gmtime())
    key = f"sec-llm:quota:{kind}:{user_id}:{day}"
    client = _client()
    if client is not None:
        try:
            pipe = client.pipeline()
            pipe.incr(key)
            pipe.expire(key, 172800, nx=True)
            used = int(pipe.execute()[0])
            return used <= limit, used
        except Exception:  # noqa: BLE001
            _mark_redis_down()

    with _memory_lock:
        if len(_quota_memory) > _MEMORY_MAX_KEYS:
            _quota_memory.clear()
        used = _quota_memory.get(key, 0) + 1
        _quota_memory[key] = used
    return used <= limit, used


# --- Access token revocation (logout / logout-all / refresh replay) ---
_REVOKED_ACCESS_PREFIX = "sec-llm:revoked:access:"
_USER_CUTOFF_PREFIX = "sec-llm:revoked:before:"
_revoked_jti: Dict[str, float] = {}
_user_cutoff: Dict[str, float] = {}


def _revocation_ttl(seconds: float) -> int:
    return max(int(seconds), 1)


def _prune_revocations(now: float) -> None:
    if len(_revoked_jti) > _MEMORY_MAX_KEYS:
        for key in [k for k, expiry in _revoked_jti.items() if expiry <= now]:
            _revoked_jti.pop(key, None)


def revoke_access_token(jti: Optional[str], ttl_seconds: float) -> None:
    """Deny one access-token jti until it would have expired anyway."""
    if not jti:
        return
    ttl = _revocation_ttl(ttl_seconds)
    now = time.time()
    with _memory_lock:
        _revoked_jti[jti] = now + ttl
        _prune_revocations(now)

    client = _client()
    if client is None:
        return
    try:
        client.setex(_REVOKED_ACCESS_PREFIX + jti, ttl, "1")
    except Exception:  # noqa: BLE001
        _mark_redis_down()


def revoke_user_access(user_id: Any, ttl_seconds: float) -> None:
    """Invalidate every access token issued up to now for this user."""
    if user_id is None:
        return
    ttl = _revocation_ttl(ttl_seconds) + 60
    now = time.time()
    key = str(user_id)
    with _memory_lock:
        _user_cutoff[key] = now
        if len(_user_cutoff) > _MEMORY_MAX_KEYS:
            _user_cutoff.clear()
            _user_cutoff[key] = now

    client = _client()
    if client is None:
        return
    try:
        client.setex(_USER_CUTOFF_PREFIX + key, ttl, now)
    except Exception:  # noqa: BLE001
        _mark_redis_down()


def access_token_revoked(jti: Any, user_id: Any, issued_at: Any) -> bool:
    """True when the token's jti was revoked, or it predates a user-wide cutoff."""
    jti_value = str(jti) if jti else ""
    now = time.time()

    if jti_value:
        with _memory_lock:
            expiry = _revoked_jti.get(jti_value)
            if expiry is not None and expiry > now:
                return True
            if expiry is not None:
                _revoked_jti.pop(jti_value, None)

    cutoff = None
    if user_id is not None:
        with _memory_lock:
            cutoff = _user_cutoff.get(str(user_id))

    client = _client()
    if client is not None:
        try:
            if jti_value and client.exists(_REVOKED_ACCESS_PREFIX + jti_value):
                return True
            if user_id is not None:
                remote = client.get(_USER_CUTOFF_PREFIX + str(user_id))
                if remote is not None:
                    cutoff = max(cutoff or 0.0, float(remote))
        except Exception:  # noqa: BLE001
            _mark_redis_down()

    if cutoff is not None and issued_at is not None:
        try:
            return float(issued_at) <= float(cutoff)
        except (TypeError, ValueError):
            return False
    return False
