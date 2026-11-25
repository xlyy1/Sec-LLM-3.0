"""RBAC helpers are pure and should stay cheap to test."""
import pytest
from fastapi import HTTPException

from core.auth.rbac import can_write, normalize_role, require_write


def test_legacy_user_maps_to_operator():
    assert normalize_role("user") == "operator"
    assert normalize_role("ADMIN") == "admin"
    assert normalize_role(None) == "viewer"


def test_viewer_is_read_only():
    assert can_write({"role": "viewer"}) is False
    assert can_write({"role": "operator"}) is True
    assert can_write({"role": "admin"}) is True

    with pytest.raises(HTTPException) as error:
        require_write({"role": "viewer"})
    assert error.value.status_code == 403
