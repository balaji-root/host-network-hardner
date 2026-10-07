"""
Tests for Phase 4 Async Port Scanner Engine (TCP & UDP) & Phase 5 Service Enumeration.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import PortInfo
from core.scanner import AsyncPortScanner, parse_port_spec
from core.enumerate import ServiceEnumerator
from db import Database


def test_parse_port_spec() -> None:
    # Test default
    default_ports = parse_port_spec(None)
    assert 80 in default_ports
    assert 443 in default_ports

    # Test comma separated
    ports = parse_port_spec("80,443,8080")
    assert ports == [80, 443, 8080]

    # Test range
    ports = parse_port_spec("8000-8005")
    assert ports == [8000, 8001, 8002, 8003, 8004, 8005]

    # Test full 65535 ports spec
    full_ports = parse_port_spec("1-65535", full=True)
    assert len(full_ports) == 65535
    assert full_ports[0] == 1
    assert full_ports[-1] == 65535


@pytest.mark.asyncio
async def test_async_port_scanner_local(tmp_path: Path) -> None:
    # Set up temporary SQLite db
    db_file = tmp_path / "test_scan.db"
    db = Database(db_path=db_file)

    # Spin up dummy socket server on localhost
    server = await asyncio.start_server(
        lambda r, w: w.close(),
        host="127.0.0.1",
        port=0
    )
    sockets = server.sockets
    assert sockets is not None and len(sockets) > 0
    listening_port = sockets[0].getsockname()[1]

    scanner = AsyncPortScanner(concurrency=10, timeout=0.5, db=db)
    results = await scanner.scan_target(
        target="127.0.0.1",
        target_ip="127.0.0.1",
        ports=[listening_port, listening_port + 1],
        protocol="tcp"
    )

    server.close()
    await server.wait_closed()

    listening_info = [r for r in results if r.port == listening_port]
    assert len(listening_info) == 1
    assert listening_info[0].state == "open"


@pytest.mark.asyncio
async def test_async_udp_port_scanner(tmp_path: Path) -> None:
    db_file = tmp_path / "test_udp.db"
    db = Database(db_path=db_file)

    scanner = AsyncPortScanner(concurrency=10, timeout=0.5, db=db)
    results = await scanner.scan_target(
        target="127.0.0.1",
        target_ip="127.0.0.1",
        ports=[53, 123],
        protocol="udp"
    )
    assert len(results) == 2
    assert results[0].protocol == "udp"


@pytest.mark.asyncio
async def test_banner_enumeration(tmp_path: Path) -> None:
    db_file = tmp_path / "test_enum.db"
    db = Database(db_path=db_file)

    # Dummy TCP server sending SSH banner
    async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_ssh, host="127.0.0.1", port=0)
    sockets = server.sockets
    assert sockets is not None and len(sockets) > 0
    ssh_port = sockets[0].getsockname()[1]

    enumerator = ServiceEnumerator(db=db, timeout=1.0)
    pinfo = PortInfo(port=ssh_port, protocol="tcp", state="open")

    await enumerator.enumerate_port("127.0.0.1", pinfo)

    server.close()
    await server.wait_closed()

    assert pinfo.service == "ssh"
    assert "SSH-2.0-OpenSSH" in (pinfo.banner or "")


@pytest.mark.asyncio
async def test_async_port_scanner_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = Database(db_path=tmp_path / "test_retry.db")
    call_count = 0

    class DummyWriter:
        def close(self) -> None: pass
        async def wait_closed(self) -> None: pass

    async def mock_open_connection(host: str, port: int) -> tuple:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise asyncio.TimeoutError()
        return None, DummyWriter()

    monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

    scanner = AsyncPortScanner(concurrency=5, timeout=0.1, retries=1, db=db)
    results = await scanner.scan_target(
        target="127.0.0.1",
        target_ip="127.0.0.1",
        ports=[12345],
        protocol="tcp"
    )

    assert len(results) == 1
    assert results[0].state == "open"
    assert call_count == 2


@pytest.mark.asyncio
async def test_filtered_port_diagnosis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = Database(db_path=tmp_path / "test_filtered.db")

    async def mock_timeout(host: str, port: int) -> tuple:
        raise asyncio.TimeoutError()

    monkeypatch.setattr(asyncio, "open_connection", mock_timeout)

    scanner = AsyncPortScanner(concurrency=5, timeout=0.1, retries=1, db=db)
    results = await scanner.scan_target(
        target="192.168.1.12",
        target_ip="192.168.1.12",
        ports=[22],
        protocol="tcp"
    )

    assert len(results) == 1
    pinfo = results[0]
    assert pinfo.port == 22
    assert pinfo.state == "filtered"
    assert pinfo.service == "ssh"
    assert pinfo.reason is not None
    assert "SYN dropped" in pinfo.reason
    assert "packet drop" in pinfo.reason

    # Verify DB persistence of filtered port
    ports_in_db = db.get_ports_for_host(1)
    assert len(ports_in_db) == 1
    assert ports_in_db[0]["port"] == 22
    assert ports_in_db[0]["state"] == "filtered"
    assert "SYN dropped" in (ports_in_db[0]["raw_evidence"] or "")


