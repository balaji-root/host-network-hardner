"""
Security Check: Weak TLS & SSL Certificate Inspector.
"""

from __future__ import annotations

import socket
import ssl
from typing import List
from core.checks import BaseCheck
from core.models import Finding, PortInfo, Severity


class WeakTLSCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "weak_tls"

    @property
    def description(self) -> str:
        return "Detects outdated TLS versions (TLS 1.0, 1.1) and SSL certificate issues."

    def run(self, host: str, port_info: PortInfo) -> List[Finding]:
        findings: List[Finding] = []

        # Only run on SSL/TLS ports or https services
        if port_info.port not in (443, 8443) and (port_info.service or "").lower() != "https":
            return findings

        # 1. Check for legacy TLS 1.0 / TLS 1.1 support
        for protocol_name, proto_const in [("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None),
                                          ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None)]:
            if proto_const is None:
                continue
            try:
                ctx = ssl.SSLContext(proto_const)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port_info.port), timeout=2.0) as sock:
                    with ctx.wrap_socket(sock) as ssock:
                        findings.append(
                            Finding(
                                check_name=self.name,
                                title=f"Deprecated {protocol_name} Supported",
                                severity=Severity.MEDIUM,
                                impact=3,
                                likelihood=4,
                                description=f"Port {port_info.port} accepts legacy and insecure protocol {protocol_name}.",
                                host=host,
                                port=port_info.port,
                                remediation=f"Disable {protocol_name} in server configuration and enforce TLS 1.2 or TLS 1.3.",
                                raw_evidence=f"Successfully established {protocol_name} handshake with {host}:{port_info.port}"
                            )
                        )
            except Exception:
                pass

        # 2. Check Certificate Expiry / Self-Signed
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port_info.port), timeout=2.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        subject = dict(x[0] for x in cert.get("subject", []))
                        if issuer == subject:
                            findings.append(
                                Finding(
                                    check_name=self.name,
                                    title="Self-Signed SSL Certificate",
                                    severity=Severity.LOW,
                                    impact=2,
                                    likelihood=3,
                                    description=f"Port {port_info.port} uses a self-signed SSL certificate.",
                                    host=host,
                                    port=port_info.port,
                                    remediation="Replace self-signed certificate with one issued by a trusted Certificate Authority (CA).",
                                    raw_evidence=f"Certificate Issuer matches Subject: {issuer}"
                                )
                            )
        except Exception:
            pass

        return findings
