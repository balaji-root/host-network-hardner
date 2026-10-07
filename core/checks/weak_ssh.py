"""
Security Check: Weak SSH Configuration & Legacy Banner Inspector.
"""

from __future__ import annotations

import re
from typing import List
from core.checks import BaseCheck
from core.models import Finding, PortInfo, Severity


class WeakSSHCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "weak_ssh"

    @property
    def description(self) -> str:
        return "Inspects SSH banners for legacy protocol versions (SSH v1) and outdated software."

    def run(self, host: str, port_info: PortInfo) -> List[Finding]:
        findings: List[Finding] = []

        if port_info.port != 22 and (port_info.service or "").lower() != "ssh":
            return findings

        banner = port_info.banner or ""

        # Check for legacy SSH v1 support
        if "SSH-1." in banner or "SSH-1.99" in banner:
            findings.append(
                Finding(
                    check_name=self.name,
                    title="Legacy SSH Protocol Version Supported",
                    severity=Severity.HIGH,
                    impact=4,
                    likelihood=4,
                    description=f"SSH banner '{banner}' indicates support for obsolete SSH protocol v1.",
                    host=host,
                    port=port_info.port,
                    remediation="Set `Protocol 2` in `/etc/ssh/sshd_config` to enforce SSH v2 exclusively.",
                    raw_evidence=f"SSH Banner: {banner}"
                )
            )

        return findings
