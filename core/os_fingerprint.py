"""
Phase 6: Passive OS Fingerprinting module for Host & Network Hardener.
Analyzes banner text and protocol artifacts to guess host OS with a confidence score.
"""

from __future__ import annotations

import re
from typing import List, Tuple, Optional
from core.models import PortInfo


class OSFingerprinter:
    """Passive OS fingerprinting engine based on banner inspection."""

    OS_PATTERNS = [
        # (Pattern, OS Name, Base Confidence)
        (r"ubuntu", "Linux (Ubuntu)", 0.85),
        (r"debian", "Linux (Debian)", 0.85),
        (r"alpine", "Linux (Alpine)", 0.80),
        (r"centos", "Linux (CentOS)", 0.85),
        (r"redhat|rhel", "Linux (Red Hat)", 0.85),
        (r"fedora", "Linux (Fedora)", 0.80),
        (r"freebsd", "BSD (FreeBSD)", 0.85),
        (r"openbsd", "BSD (OpenBSD)", 0.85),
        (r"win64|win32|windows|microsoft-iis|microsoft-httpapi", "Windows Server / Desktop", 0.85),
        (r"darwin|macOS|apple", "macOS", 0.80),
        (r"linux", "Linux (Generic)", 0.60),
        (r"unix", "Unix (Generic)", 0.50),
    ]

    def fingerprint(self, open_ports: List[PortInfo]) -> Tuple[str, float]:
        """
        Analyze open ports and their banners to guess the host OS.
        Returns a tuple of (os_guess, confidence_score).
        """
        if not open_ports:
            return "Unknown OS", 0.0

        matches: List[Tuple[str, float]] = []

        for pinfo in open_ports:
            banner = (pinfo.banner or "").lower()
            if not banner:
                continue

            for pattern, os_name, confidence in self.OS_PATTERNS:
                if re.search(pattern, banner, re.IGNORECASE):
                    matches.append((os_name, confidence))

        if not matches:
            return "Unknown OS", 0.0

        # Sort matches by confidence score descending
        matches.sort(key=lambda x: x[1], reverse=True)
        best_os, top_conf = matches[0]

        # Boost confidence slightly if multiple ports confirm the same OS family
        same_count = sum(1 for os_name, _ in matches if os_name == best_os)
        if same_count > 1:
            top_conf = min(0.98, top_conf + 0.05 * (same_count - 1))

        return best_os, round(top_conf, 2)
