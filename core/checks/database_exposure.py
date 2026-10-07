"""
Security Check: Exposed Database Port Detector.
"""

from __future__ import annotations

from typing import List
from core.checks import BaseCheck
from core.models import Finding, PortInfo, Severity


class DatabaseExposureCheck(BaseCheck):
    DB_PORTS = {
        3306: ("MySQL", "MySQL database engine listener."),
        5432: ("PostgreSQL", "PostgreSQL relational database service."),
        6379: ("Redis", "Redis in-memory data store."),
        27017: ("MongoDB", "MongoDB NoSQL database engine."),
        1433: ("MSSQL", "Microsoft SQL Server listener."),
        9200: ("Elasticsearch", "Elasticsearch cluster node REST interface."),
    }

    @property
    def name(self) -> str:
        return "database_exposure"

    @property
    def description(self) -> str:
        return "Identifies database ports exposed directly to public/external network interfaces."

    def run(self, host: str, port_info: PortInfo) -> List[Finding]:
        findings: List[Finding] = []

        if port_info.port in self.DB_PORTS:
            db_name, detail = self.DB_PORTS[port_info.port]

            findings.append(
                Finding(
                    check_name=self.name,
                    title=f"Exposed Database Service ({db_name})",
                    severity=Severity.HIGH,
                    impact=5,
                    likelihood=3,
                    description=f"Database port {port_info.port} ({db_name}) is exposed on the network interface. {detail}",
                    host=host,
                    port=port_info.port,
                    remediation=f"Bind {db_name} service to 127.0.0.1 (loopback) or restrict port {port_info.port} using a host firewall.",
                    raw_evidence=f"Port {port_info.port}/tcp detected OPEN with banner/service: '{port_info.banner or port_info.service}'."
                )
            )

        return findings
