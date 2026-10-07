"""
Data models and type definitions for Host & Network Hardener.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class Finding:
    """Security finding discovered during scanning/checking."""
    check_name: str
    title: str
    severity: Severity
    impact: int  # 1-5 scale
    likelihood: int  # 1-5 scale
    description: str
    host: str
    port: Optional[int] = None
    remediation: Optional[str] = None
    raw_evidence: Optional[str] = None
    risk_score: int = 0

    def __post_init__(self):
        if self.risk_score == 0:
            self.risk_score = self.impact * self.likelihood


@dataclass
class PortInfo:
    """Information regarding a scanned port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"  # open, closed, filtered
    service: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    version_info: Optional[str] = None
    raw_evidence: Optional[str] = None
    reason: Optional[str] = None  # Diagnostic evidence on why/how the port is in this state


@dataclass
class HostTarget:
    """Target representation during pipeline execution."""
    target: str
    ip: Optional[str] = None
    is_live: bool = False
    open_ports: List[PortInfo] = field(default_factory=list)
    os_guess: Optional[str] = None
    os_confidence: Optional[float] = None
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ScopeConfig:
    """Parsed scope configuration."""
    allowed_targets: List[str] = field(default_factory=list)
    excluded_targets: List[str] = field(default_factory=list)
    max_rate_per_sec: int = 50
    scan_window: str = "00:00-23:59"
