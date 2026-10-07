"""
Security Check: Exposed Administrative Panels Detector.
"""

from __future__ import annotations

import requests
from typing import List
from core.checks import BaseCheck
from core.models import Finding, PortInfo, Severity


class ExposedAdminPanelsCheck(BaseCheck):
    ADMIN_PATHS = ["/admin", "/admin/", "/wp-admin/", "/dashboard", "/phpmyadmin/"]

    @property
    def name(self) -> str:
        return "exposed_admin_panels"

    @property
    def description(self) -> str:
        return "Probes HTTP/HTTPS ports for publicly accessible administrative web interfaces."

    def run(self, host: str, port_info: PortInfo) -> List[Finding]:
        findings: List[Finding] = []

        if port_info.port not in (80, 443, 8000, 8080, 8443) and (port_info.service or "").lower() not in ("http", "https"):
            return findings

        scheme = "https" if port_info.port in (443, 8443) or (port_info.service or "").lower() == "https" else "http"

        for path in self.ADMIN_PATHS:
            url = f"{scheme}://{host}:{port_info.port}{path}"
            try:
                resp = requests.get(url, timeout=2.0, verify=False, allow_redirects=True)
                if resp.status_code in (200, 401):
                    findings.append(
                        Finding(
                            check_name=self.name,
                            title=f"Exposed Admin Panel at {path}",
                            severity=Severity.HIGH if resp.status_code == 200 else Severity.MEDIUM,
                            impact=4,
                            likelihood=4,
                            description=f"Publicly accessible admin interface found at {url} (HTTP {resp.status_code}).",
                            host=host,
                            port=port_info.port,
                            remediation="Restrict access to administrative panels using IP whitelisting or VPN authentication.",
                            raw_evidence=f"GET {url} -> HTTP {resp.status_code}"
                        )
                    )
            except Exception:
                pass

        return findings
