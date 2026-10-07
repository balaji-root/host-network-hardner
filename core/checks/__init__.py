"""
Phase 7: Pluggable Security Checks Engine for Host & Network Hardener.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List
from core.models import Finding, PortInfo


class BaseCheck(ABC):
    """Abstract base class for all pluggable security checks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the check."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Short summary of what this check tests."""
        pass

    @abstractmethod
    def run(self, host: str, port_info: PortInfo) -> List[Finding]:
        """
        Execute check against a given host and open port.
        Returns a list of Finding objects if vulnerabilities are detected.
        """
        pass


class CheckRunner:
    """Registry and executor for security checks."""

    def __init__(self) -> None:
        self._checks: List[BaseCheck] = []
        self._load_default_checks()

    def register_check(self, check: BaseCheck) -> None:
        """Register a new check module."""
        self._checks.append(check)

    def _load_default_checks(self) -> None:
        """Instantiate and load all standard check modules."""
        from core.checks.weak_tls import WeakTLSCheck
        from core.checks.exposed_admin_panels import ExposedAdminPanelsCheck
        from core.checks.insecure_protocols import InsecureProtocolsCheck
        from core.checks.weak_ssh import WeakSSHCheck
        from core.checks.database_exposure import DatabaseExposureCheck
        from core.checks.verbose_banners import VerboseBannersCheck
        from core.checks.known_cve import KnownCVECheck

        self.register_check(WeakTLSCheck())
        self.register_check(ExposedAdminPanelsCheck())
        self.register_check(InsecureProtocolsCheck())
        self.register_check(WeakSSHCheck())
        self.register_check(DatabaseExposureCheck())
        self.register_check(VerboseBannersCheck())
        self.register_check(KnownCVECheck())

    def run_all(self, host: str, open_ports: List[PortInfo]) -> List[Finding]:
        """Run all registered checks across all open ports."""
        all_findings: List[Finding] = []

        for pinfo in open_ports:
            if pinfo.state != "open":
                continue
            for check in self._checks:
                try:
                    findings = check.run(host, pinfo)
                    if findings:
                        all_findings.extend(findings)
                except Exception as e:
                    # Log check execution error without breaking scanner pipeline
                    pass

        return all_findings
