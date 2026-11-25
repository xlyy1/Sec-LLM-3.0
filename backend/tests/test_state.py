"""Shared-state fallbacks: revocation and quotas must work without Redis."""
import time

from core import state


def test_jti_revocation_uses_memory_when_redis_disabled():
    jti = f"test-jti-{time.time_ns()}"
    assert state.access_token_revoked(jti, None, None) is False
    state.revoke_access_token(jti, 60)
    assert state.access_token_revoked(jti, None, None) is True


def test_user_cutoff_revokes_older_tokens_only():
    user_id = 987654
    state.revoke_user_access(user_id, 60)
    now = time.time()
    assert state.access_token_revoked(None, user_id, now - 10) is True
    assert state.access_token_revoked(None, user_id, now + 10) is False


def test_quota_counter_in_memory():
    user_id = 987655
    allowed, used = state.consume_quota(user_id, "unit", 2)
    assert allowed is True and used >= 1
    allowed, used = state.consume_quota(user_id, "unit", 2)
    assert allowed is True and used >= 2
    allowed, _ = state.consume_quota(user_id, "unit", 2)
    assert allowed is False
