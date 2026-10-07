"""
Unit tests for Phase 6 OS Fingerprinting engine.
"""

from __future__ import annotations

from core.models import PortInfo
from core.os_fingerprint import OSFingerprinter


def test_os_fingerprint_unknown():
    fingerprinter = OSFingerprinter()
    os_guess, conf = fingerprinter.fingerprint([])
    assert os_guess == "Unknown OS"
    assert conf == 0.0


def test_os_fingerprint_ubuntu():
    fingerprinter = OSFingerprinter()
    ports = [
        PortInfo(port=22, state="open", service="ssh", banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"),
        PortInfo(port=80, state="open", service="http", banner="HTTP/200 (Server: Apache/2.4.52 (Ubuntu))")
    ]
    os_guess, conf = fingerprinter.fingerprint(ports)
    assert os_guess == "Linux (Ubuntu)"
    assert conf >= 0.85


def test_os_fingerprint_windows():
    fingerprinter = OSFingerprinter()
    ports = [
        PortInfo(port=80, state="open", service="http", banner="HTTP/200 (Server: Microsoft-IIS/10.0)")
    ]
    os_guess, conf = fingerprinter.fingerprint(ports)
    assert os_guess == "Windows Server / Desktop"
    assert conf >= 0.80
