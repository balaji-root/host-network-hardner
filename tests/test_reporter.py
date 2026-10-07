"""
Unit tests for core/reporter.py PDF Report Generator.
"""

import tempfile
from pathlib import Path
import pytest

from core.reporter import PDFReportGenerator, safe_text
from core.models import Finding, Severity, PortInfo
from db import Database


def test_safe_text():
    assert safe_text("Normal text") == "Normal text"
    assert safe_text("<b>Bold</b> & <script>") == "&lt;b&gt;Bold&lt;/b&gt; &amp; &lt;script&gt;"
    assert safe_text(None) == ""
    # Test unicode fallback
    res = safe_text("Port \u02cc info")
    assert isinstance(res, str)


def test_generate_report_basic(tmp_path):
    reporter = PDFReportGenerator(output_dir=tmp_path)
    data = {
        "target": "example.com",
        "target_ip": "93.184.216.34",
        "status": "live",
        "discovery_method": "ICMP Echo",
        "total_ports": 100,
        "open_ports": [],
        "filtered_ports": [],
        "findings": [],
    }

    out_pdf = reporter.generate_report(data, output_path=tmp_path / "test_basic.pdf")
    assert out_pdf.exists()
    assert out_pdf.stat().st_size > 1000

    # Verify PDF magic bytes
    with open(out_pdf, "rb") as f:
        magic = f.read(4)
        assert magic == b"%PDF"


def test_generate_report_comprehensive(tmp_path):
    reporter = PDFReportGenerator(output_dir=tmp_path)
    finding1 = Finding(
        check_name="ssh_audit",
        title="Outdated OpenSSH 6.6 Detected",
        severity=Severity.HIGH,
        impact=4,
        likelihood=4,
        description="The host runs an end-of-life OpenSSH daemon susceptible to user enumeration.",
        host="45.33.32.156",
        port=22,
        remediation="Upgrade OpenSSH to version 9.6 or later.",
        raw_evidence="SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
        risk_score=16
    )

    port1 = PortInfo(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        banner="SSH-2.0-OpenSSH_6.6.1p1",
        version_info="OpenSSH 6.6.1p1"
    )
    port2 = PortInfo(
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        banner="Apache/2.4.7",
        version_info="Apache 2.4.7 (Ubuntu)"
    )
    filtered_port = PortInfo(
        port=445,
        protocol="tcp",
        state="filtered",
        service="microsoft-ds",
        reason="No response / SYN dropped after 2 probe(s)"
    )

    data = {
        "target": "scanme.nmap.org",
        "target_ip": "45.33.32.156",
        "ptr_record": "scanme.nmap.org",
        "status": "live",
        "discovery_method": "TCP Probe (Port 80)",
        "os_guess": "Linux (Ubuntu)",
        "os_confidence": 0.95,
        "dns_records": {"A": ["45.33.32.156"]},
        "scope_status": "Authorized",
        "total_ports": 65535,
        "open_ports": [port1, port2],
        "filtered_ports": [filtered_port],
        "closed_tcp_count": 65500,
        "filtered_tcp_count": 33,
        "duration": 4.25,
        "scan_date": "September 29, 2026 - 16:30 UTC",
        "findings": [finding1],
    }

    out_pdf = reporter.generate_report(data, output_path=tmp_path / "comprehensive_report.pdf")
    assert out_pdf.exists()
    assert out_pdf.stat().st_size > 5000


def test_export_from_db(tmp_path):
    db_file = tmp_path / "test_scan.db"
    db = Database(db_path=db_file)

    host_id = db.upsert_host(
        target="192.168.1.100",
        ip="192.168.1.100",
        status="live",
        os_guess="Linux",
        os_confidence=0.85
    )
    db.upsert_port(
        host_id=host_id,
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        banner="nginx/1.18.0"
    )
    db.add_finding(
        host_id=host_id,
        port=80,
        check_name="http_headers",
        title="Missing Content-Security-Policy",
        severity="Medium",
        impact=3,
        likelihood=3,
        risk_score=9,
        description="Missing CSP header exposes web application to cross-site scripting.",
        remediation="Configure Content-Security-Policy header in Nginx configuration."
    )

    reporter = PDFReportGenerator(output_dir=tmp_path)
    pdf_path = reporter.export_from_db(db, "192.168.1.100", output_path=tmp_path / "db_export.pdf")
    assert pdf_path is not None
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 3000

    # Non-existent host returns None
    assert reporter.export_from_db(db, "nonexistent.host") is None
