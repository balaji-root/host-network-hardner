"""
Security Check: Known CVE & Software Version Vulnerability Assessor.
Matches identified service versions against known CVE advisories and security vulnerabilities.
"""

from __future__ import annotations

from typing import List
from core.checks import BaseCheck
from core.models import Finding, PortInfo, Severity


class KnownCVECheck(BaseCheck):
    # Tuple format: (product_name, version_substring/pattern, cve_id, title, severity, impact, likelihood, description, remediation)
    KNOWN_ADVISORIES = [
        (
            "vsftpd", "2.3.4", "CVE-2011-2523",
            "vsftpd 2.3.4 Backdoor Command Execution",
            Severity.CRITICAL, 5, 5,
            "vsftpd version 2.3.4 contains a malicious backdoor that opens a root shell on port 6200 when a username containing ':)' is supplied.",
            "Upgrade vsftpd immediately to version 3.0.0 or higher."
        ),
        (
            "Apache httpd", "2.4.49", "CVE-2021-41773",
            "Apache httpd 2.4.49 Path Traversal & Remote Code Execution",
            Severity.CRITICAL, 5, 5,
            "Path traversal flaw in Apache HTTP Server 2.4.49 allows unauthenticated remote attackers to read arbitrary files or execute code if mod_cgi is enabled.",
            "Update Apache HTTP Server to version 2.4.51 or higher immediately."
        ),
        (
            "Apache httpd", "2.4.50", "CVE-2021-42013",
            "Apache httpd 2.4.50 Path Traversal & Remote Code Execution",
            Severity.CRITICAL, 5, 5,
            "Incomplete fix for CVE-2021-41773 in Apache 2.4.50 allows remote file disclosure and code execution.",
            "Update Apache HTTP Server to version 2.4.51 or higher."
        ),
        (
            "OpenSSH", "6.6.1", "CVE-2016-0777",
            "OpenSSH 6.6.1 Outdated Version / Roaming Data Leakage",
            Severity.HIGH, 4, 3,
            "OpenSSH 6.6.1 contains enabled-by-default experimental roaming support allowing malicious SSH servers to leak client private keys.",
            "Upgrade OpenSSH to version 7.2p1 or higher, or disable UseRoaming in ssh_config."
        ),
        (
            "OpenSSH", "8.4p1", "CVE-2023-38408",
            "OpenSSH PKCS#11 Provider Remote Code Execution Advisory",
            Severity.HIGH, 4, 3,
            "OpenSSH versions prior to 9.3p2 contain a vulnerability in pkcs11-provider module handling during SSH agent forwarding.",
            "Upgrade OpenSSH to version 9.3p2 or higher and restrict SSH agent forwarding."
        ),
    ]

    @property
    def name(self) -> str:
        return "known_cve_lookup"

    @property
    def description(self) -> str:
        return "Correlates detected software versions against known CVE security advisories."

    def run(self, host: str, port_info: PortInfo) -> List[Finding]:
        findings: List[Finding] = []

        product = (port_info.product or "").lower()
        version = (port_info.version or "").lower()
        banner = (port_info.banner or "").lower()

        if not product and not version and not banner:
            return findings

        for prod_name, ver_pattern, cve_id, title, severity, impact, likelihood, desc, remediation in self.KNOWN_ADVISORIES:
            if prod_name.lower() in product or prod_name.lower() in banner:
                if ver_pattern in version or ver_pattern in banner:
                    findings.append(
                        Finding(
                            check_name=self.name,
                            title=f"[{cve_id}] {title}",
                            severity=severity,
                            impact=impact,
                            likelihood=likelihood,
                            description=desc,
                            host=host,
                            port=port_info.port,
                            remediation=remediation,
                            raw_evidence=f"Detected Software: {port_info.version_info or port_info.banner} (Matches {cve_id})"
                        )
                    )

        return findings
