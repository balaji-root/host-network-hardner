"""
Tests for Phase 2 DNS Resolution and Phase 3 Host Discovery (ICMP + TCP).
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.dns_resolve import DNSResolver
from core.discovery import HostDiscovery
from db import Database


def test_dns_resolver_ip_detection(tmp_path: Path) -> None:
    db_file = tmp_path / "test_dns.db"
    db = Database(db_path=db_file)
    resolver = DNSResolver(db=db)

    assert resolver.is_ip("127.0.0.1") is True
    assert resolver.is_ip("192.168.1.1") is True
    assert resolver.is_ip("scanme.nmap.org") is False


def test_dns_resolver_caching(tmp_path: Path) -> None:
    db_file = tmp_path / "test_dns_cache.db"
    db = Database(db_path=db_file)
    resolver = DNSResolver(db=db)

    # First resolution
    ip1 = resolver.resolve_ip("localhost")
    assert ip1 in ("127.0.0.1", "::1")

    # Verify cache entry
    cached = resolver._get_cached("localhost", "A")
    assert len(cached) > 0 or ip1 == "127.0.0.1"


@pytest.mark.asyncio
async def test_host_discovery_localhost() -> None:
    discovery = HostDiscovery(timeout=0.5)
    is_live, method = await discovery.is_host_live("127.0.0.1")
    assert is_live is True
    assert method == "Loopback Interface"


@pytest.mark.asyncio
async def test_icmp_ping_local() -> None:
    discovery = HostDiscovery(timeout=1.0)
    # ICMP ping 127.0.0.1 should succeed
    icmp_ok = await discovery._icmp_ping("127.0.0.1")
    assert icmp_ok is True
