"""
Tests for database storage layer (db.py).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import pytest

# Ensure project root is in sys.path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import Database



@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path=db_path)
        yield db


def test_db_initialization(temp_db):
    assert temp_db.db_path.exists()
    with temp_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        assert {"hosts", "ports", "findings", "dns_cache"}.issubset(tables)


def test_upsert_host_and_ports(temp_db):
    host_id = temp_db.upsert_host(
        target="127.0.0.1",
        ip="127.0.0.1",
        status="live",
        os_guess="Linux",
        os_confidence=0.85
    )
    assert host_id > 0

    port_id = temp_db.upsert_port(
        host_id=host_id,
        port=8080,
        protocol="tcp",
        state="open",
        service="http",
        banner="SimpleHTTP/0.6 Python/3.13",
        raw_evidence="HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Python/3.13"
    )
    assert port_id > 0

    hosts = temp_db.get_hosts()
    assert len(hosts) == 1
    assert hosts[0]["target"] == "127.0.0.1"
    assert hosts[0]["status"] == "live"


def test_add_finding(temp_db):
    host_id = temp_db.upsert_host(target="127.0.0.1", ip="127.0.0.1", status="live")
    
    finding_id = temp_db.add_finding(
        host_id=host_id,
        port=8080,
        check_name="exposed_http_server",
        title="Development HTTP Server Exposed",
        severity="Medium",
        impact=3,
        likelihood=4,
        risk_score=12,
        description="A Python simple HTTP server is running on port 8080 without authentication.",
        remediation="Bind to localhost or add authentication.",
        raw_evidence="Server: SimpleHTTP/0.6"
    )
    assert finding_id > 0

    findings = temp_db.get_findings_for_host(host_id)
    assert len(findings) == 1
    assert findings[0]["title"] == "Development HTTP Server Exposed"
    assert findings[0]["risk_score"] == 12


def test_scope_targets_db(temp_db):
    target_id = temp_db.add_scope_target("192.168.1.100", target_type="allowed")
    assert target_id > 0

    targets = temp_db.get_scope_targets("allowed")
    assert any(t["target"] == "192.168.1.100" for t in targets)

    # Test removal
    removed = temp_db.remove_scope_target("192.168.1.100")
    assert removed is True
    assert not any(t["target"] == "192.168.1.100" for t in temp_db.get_scope_targets("allowed"))


def test_delete_host_and_clear_scans(temp_db):
    host_id = temp_db.upsert_host(target="10.0.0.1", ip="10.0.0.1", status="live")
    temp_db.upsert_port(host_id=host_id, port=80, protocol="tcp", state="open", service="http")

    summary = temp_db.get_hosts_summary()
    assert len(summary) >= 1
    assert any(s["target"] == "10.0.0.1" for s in summary)

    # Test single host deletion
    del_ok = temp_db.delete_host("10.0.0.1")
    assert del_ok is True
    assert not any(s["target"] == "10.0.0.1" for s in temp_db.get_hosts_summary())

    # Test clear_all_scans
    temp_db.upsert_host(target="10.0.0.2", ip="10.0.0.2", status="live")
    stats = temp_db.clear_all_scans()
    assert stats["hosts_cleared"] >= 1
    assert len(temp_db.get_hosts_summary()) == 0


if __name__ == "__main__":
    pytest.main(["-v", __file__])


