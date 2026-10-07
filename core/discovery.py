"""
Phase 3: Host Discovery module for Host & Network Hardener.
Checks if a target host is live using ICMP echo requests (ping) and fast async TCP probes.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import List, Optional, Tuple


class HostDiscovery:
    """Discovers whether a target IP/host is active on the network using ICMP + TCP."""

    DEFAULT_DISCOVERY_PORTS = [80, 443, 22, 8080, 445, 135]

    def __init__(self, timeout: float = 1.5, ports: Optional[List[int]] = None):
        self.timeout = timeout
        self.ports = ports or self.DEFAULT_DISCOVERY_PORTS

    async def is_host_live(self, target_ip: str) -> Tuple[bool, str]:
        """
        Check if host is live.
        Returns (is_live: bool, method_used: str).
        Tries ICMP ping first, then TCP connect probes as fallback.
        """
        if target_ip in ("127.0.0.1", "localhost", "::1"):
            return True, "Loopback Interface"

        # 1. Try ICMP Echo Ping
        icmp_success = await self._icmp_ping(target_ip)
        if icmp_success:
            return True, "ICMP Echo Reply (Ping)"

        # 2. Fallback to TCP SYN/Connect probes
        tasks = [self._check_tcp_port(target_ip, port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if res is True:
                return True, "TCP SYN/RST Response"

        return False, "No response to ICMP or TCP probes"

    async def _icmp_ping(self, host: str) -> bool:
        """Send ICMP echo request using system ping binary."""
        # Windows uses -n 1 -w <ms>, Linux/macOS uses -c 1 -W <sec>
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), host]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            returncode = await asyncio.wait_for(proc.wait(), timeout=self.timeout + 1.0)
            return returncode == 0
        except Exception:
            return False

    async def _check_tcp_port(self, host: str, port: int) -> bool:
        """TCP Connect check."""
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except ConnectionRefusedError:
            # Connection refused means host sent TCP RST - host is live!
            return True
        except (asyncio.TimeoutError, OSError):
            return False
