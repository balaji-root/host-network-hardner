"""
Unit tests for Phase 7 Pluggable Security Checks engine.
"""

from __future__ import annotations

from core.checks import CheckRunner
from core.checks.insecure_protocols import InsecureProtocolsCheck
from core.checks.database_exposure import DatabaseExposureCheck
from core.checks.verbose_banners import VerboseBannersCheck
from core.checks.weak_ssh import WeakSSHCheck
from core.models import PortInfo


def test_insecure_protocols_check():
    check = InsecureProtocolsCheck()
    pinfo = PortInfo(port=23, state="open", service="telnet")
    findings = check.run("127.0.0.1", pinfo)
    assert len(findings) == 1
    assert "Unencrypted Cleartext Protocol" in findings[0].title
    assert findings[0].risk_score > 0


def test_database_exposure_check():
    check = DatabaseExposureCheck()
    pinfo = PortInfo(port=3306, state="open", service="mysql", banner="5.7.34-log")
    findings = check.run("127.0.0.1", pinfo)
    assert len(findings) == 1
    assert "Exposed Database Service" in findings[0].title
    assert findings[0].impact == 5


def test_verbose_banners_check():
    check = VerboseBannersCheck()
    pinfo = PortInfo(port=80, state="open", service="http", banner="Server: Apache/2.4.49 (Ubuntu)")
    findings = check.run("127.0.0.1", pinfo)
    assert len(findings) == 1
    assert "Verbose Software Banner" in findings[0].title


def test_weak_ssh_check():
    check = WeakSSHCheck()
    pinfo = PortInfo(port=22, state="open", service="ssh", banner="SSH-1.99-OpenSSH_3.8.1p1")
    findings = check.run("127.0.0.1", pinfo)
    assert len(findings) == 1
    assert "Legacy SSH Protocol" in findings[0].title


def test_check_runner_all():
    runner = CheckRunner()
    ports = [
        PortInfo(port=21, state="open", service="ftp"),
        PortInfo(port=6379, state="open", service="redis", banner="Redis server v=6.2.6"),
    ]
    findings = runner.run_all("127.0.0.1", ports)
    assert len(findings) >= 2
