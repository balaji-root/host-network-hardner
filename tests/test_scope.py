"""
Tests for Phase 1: Scope Validation Safety Gate.
Verifies that out-of-scope targets are strictly rejected before any network calls.
"""

from __future__ import annotations

import socket
import sys
from datetime import datetime
from pathlib import Path
import pytest

# Ensure project root is in sys.path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.scope import ScopeValidator, ScopeViolationError



@pytest.fixture
def custom_scope_validator():
    raw_config = {
        "allowed_targets": [
            "127.0.0.1",
            "localhost",
            "::1",
            "192.168.1.0/24",
            "scanme.nmap.org",
            "*.internal.lab",
        ],
        "excluded_targets": [
            "192.168.1.1",     # Default gateway excluded
            "127.0.0.99",
            "prod.internal.lab",
        ],
        "max_rate_per_sec": 50,
        "scan_window": "09:00-17:00",
    }
    return ScopeValidator(raw_config=raw_config)


def test_allowed_exact_ip(custom_scope_validator):
    ok, msg = custom_scope_validator.is_in_scope("127.0.0.1")
    assert ok is True
    assert "matches authorized scope" in msg


def test_allowed_cidr_range(custom_scope_validator):
    ok, msg = custom_scope_validator.is_in_scope("192.168.1.55")
    assert ok is True


def test_allowed_hostname(custom_scope_validator):
    ok, msg = custom_scope_validator.is_in_scope("scanme.nmap.org")
    assert ok is True
    ok, msg = custom_scope_validator.is_in_scope("localhost")
    assert ok is True


def test_allowed_url_target(custom_scope_validator):
    ok, msg = custom_scope_validator.is_in_scope("http://scanme.nmap.org/index.html")
    assert ok is True
    assert "scanme.nmap.org" in msg


def test_allowed_wildcard_domain(custom_scope_validator):
    ok, msg = custom_scope_validator.is_in_scope("web.internal.lab")
    assert ok is True


def test_rejected_out_of_scope_ip(custom_scope_validator):
    ok, msg = custom_scope_validator.is_in_scope("8.8.8.8")
    assert ok is False
    assert "not in authorized scope" in msg


def test_rejected_out_of_scope_domain(custom_scope_validator):
    ok, msg = custom_scope_validator.is_in_scope("unauthorized.target.com")
    assert ok is False
    assert "not in authorized scope" in msg


def test_excluded_target_overrides_allowed(custom_scope_validator):
    # 192.168.1.1 is inside 192.168.1.0/24, but explicitly in excluded_targets
    ok, msg = custom_scope_validator.is_in_scope("192.168.1.1")
    assert ok is False
    assert "explicitly excluded" in msg

    # 127.0.0.99 is explicitly excluded
    ok, msg = custom_scope_validator.is_in_scope("127.0.0.99")
    assert ok is False
    assert "explicitly excluded" in msg

    # prod.internal.lab matches *.internal.lab, but explicitly excluded
    ok, msg = custom_scope_validator.is_in_scope("prod.internal.lab")
    assert ok is False
    assert "explicitly excluded" in msg


def test_enforce_scope_raises_exception(custom_scope_validator):
    with pytest.raises(ScopeViolationError, match="Target not authorized"):
        custom_scope_validator.enforce_scope("10.0.0.1", check_time=datetime(2026, 1, 1, 10, 0))


def test_scan_window_validation(custom_scope_validator):
    # Window is 09:00 - 17:00
    valid_time = datetime(2026, 1, 1, 14, 30)
    in_window, msg = custom_scope_validator.is_in_scan_window(valid_time)
    assert in_window is True

    invalid_time = datetime(2026, 1, 1, 20, 15)
    in_window, msg = custom_scope_validator.is_in_scan_window(invalid_time)
    assert in_window is False

    # Should raise error if outside window
    with pytest.raises(ScopeViolationError, match="outside allowed scan window"):
        custom_scope_validator.enforce_scope("127.0.0.1", check_time=invalid_time)


def test_zero_network_calls_guarantee(monkeypatch, custom_scope_validator):
    """Ensure scope validation makes no socket or DNS network calls."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("Network socket call attempted during Phase 1 Scope Check!")

    def guarded_getaddrinfo(*args, **kwargs):
        raise RuntimeError("DNS resolution attempted during Phase 1 Scope Check!")

    monkeypatch.setattr(socket, "socket", guarded_socket)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)

    # Perform multiple scope checks - must not trigger any socket/DNS activity
    custom_scope_validator.is_in_scope("127.0.0.1")
    custom_scope_validator.is_in_scope("scanme.nmap.org")
    custom_scope_validator.is_in_scope("unauthorized.com")
    custom_scope_validator.is_in_scope("192.168.1.1")


def test_default_scope_yaml_loading():
    config_file = Path(__file__).resolve().parent.parent / "config" / "scope.yaml"
    validator = ScopeValidator(config_path=config_file)
    ok, _ = validator.is_in_scope("127.0.0.1")
    assert ok is True
    ok, _ = validator.is_in_scope("scanme.nmap.org")
    assert ok is True
    ok, _ = validator.is_in_scope("8.8.8.8")
    assert ok is False


def test_add_allowed_target(custom_scope_validator):
    # Initially 10.10.10.10 is out of scope
    ok, _ = custom_scope_validator.is_in_scope("10.10.10.10")
    assert ok is False

    # Dynamically authorize target
    custom_scope_validator.add_allowed_target("10.10.10.10")
    ok, msg = custom_scope_validator.is_in_scope("10.10.10.10")
    assert ok is True
    assert "matches authorized scope" in msg


def test_add_and_remove_target_with_yaml_and_db(tmp_path: Path):
    from db import Database

    yaml_file = tmp_path / "scope.yaml"
    db_file = tmp_path / "test_scope.db"
    db = Database(db_path=db_file)

    # Initial scope validator
    validator = ScopeValidator(config_path=yaml_file, raw_config={"allowed_targets": ["127.0.0.1"]}, db=db)
    validator.config_path = yaml_file

    # 1. Add target
    added = validator.add_target("192.168.1.150", target_type="allowed", persist=True, db=db)
    assert added is True

    ok, _ = validator.is_in_scope("192.168.1.150")
    assert ok is True

    # Verify persisted to YAML
    assert yaml_file.exists()
    reloaded_validator = ScopeValidator(config_path=yaml_file, db=db)
    ok, _ = reloaded_validator.is_in_scope("192.168.1.150")
    assert ok is True

    # Verify persisted to DB
    db_targets = db.get_scope_targets("allowed")
    assert any(t["target"] == "192.168.1.150" for t in db_targets)

    # 2. Remove target
    removed = validator.remove_target("192.168.1.150", target_type="allowed", persist=True, db=db)
    assert removed is True

    ok, _ = validator.is_in_scope("192.168.1.150")
    assert ok is False

    # Verify removed from YAML and DB
    reloaded_after_del = ScopeValidator(config_path=yaml_file)
    ok, _ = reloaded_after_del.is_in_scope("192.168.1.150")
    assert ok is False
    assert not any(t["target"] == "192.168.1.150" for t in db.get_scope_targets("allowed"))


if __name__ == "__main__":
    pytest.main(["-v", __file__])



