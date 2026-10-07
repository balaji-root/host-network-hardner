"""
Security Check: Insecure Cleartext Protocols Detector.
"""

from __future__ import annotations

from typing import List
from core.checks import BaseCheck
from core.models import Finding, PortInfo, Severity


class InsecureProtocolsCheck(BaseCheck):
    CLEAR_TEXT_PORTS = {
        21: ("FTP", "FTP transmits credentials and data in plaintext."),
        23: ("Telnet", "Telnet is unencrypted and vulnerable to eavesdropping and MITM attacks."),
        80: ("HTTP", "HTTP operates without SSL/TLS encryption."),
        110: ("POP3", "POP3 transmits email login credentials in cleartext."),
        143: ("IMAP", "IMAP transmits email login credentials in cleartext."),
    }

    @property
    def name(self) -> str:
        return "insecure_protocols"

    @property
    def description(self) -> str:
        return "Flags unencrypted cleartext services (Telnet, FTP, HTTP, POP3, IMAP)."

    def run(self, host: str, port_info: PortInfo) -> List[Finding]:
        findings: List[Finding] = []

        if port_info.port in self.CLEAR_TEXT_PORTS:
            proto_name, detail = self.CLEAR_TEXT_PORTS[port_info.port]
            severity = Severity.HIGH if port_info.port == 23 else Severity.MEDIUM
            impact = 4 if port_info.port in (21, 23) else 3

            findings.append(
                Finding(
                    check_name=self.name,
                    title=f"Unencrypted Cleartext Protocol ({proto_name})",
                    severity=severity,
                    impact=impact,
                    likelihood=4,
                    description=f"Port {port_info.port}/tcp is running unencrypted {proto_name}. {detail}",
                    host=host,
                    port=port_info.port,
                    remediation=f"Migrate from {proto_name} to an encrypted alternative (e.g. SSH/SFTP, HTTPS, IMAPS).",
                    raw_evidence=f"Port {port_info.port} detected as open with service '{port_info.service or proto_name}'."
                )
            )

        return findings
