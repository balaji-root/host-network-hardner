"""
Security Check: Verbose Banner & Version Leak Detector.
"""

from __future__ import annotations

import re
from typing import List
from core.checks import BaseCheck
from core.models import Finding, PortInfo, Severity


class VerboseBannersCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "verbose_banners"

    @property
    def description(self) -> str:
        return "Detects overly informative banners revealing exact software and OS kernel versions."

    def run(self, host: str, port_info: PortInfo) -> List[Finding]:
        findings: List[Finding] = []
        banner = port_info.banner or ""

        if not banner:
            return findings

        # Check for explicit software version numbers (e.g. Apache/2.4.49, OpenSSH_8.9p1, Ubuntu)
        if re.search(r"(Apache|nginx|OpenSSH|Lighttpd|Tomcat|IIS)/\d+\.\d+", banner, re.IGNORECASE):
            findings.append(
                Finding(
                    check_name=self.name,
                    title="Verbose Software Banner / Version Disclosure",
                    severity=Severity.LOW,
                    impact=2,
                    likelihood=4,
                    description=f"Port {port_info.port} reveals detailed version information in its banner: '{banner}'.",
                    host=host,
                    port=port_info.port,
                    remediation="Configure server software to suppress exact version strings (e.g. `ServerTokens Prod` in Apache, `server_tokens off` in Nginx).",
                    raw_evidence=f"Banner text: {banner}"
                )
            )

        return findings
