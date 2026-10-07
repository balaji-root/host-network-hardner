"""
Traceroute module for Aggressive Scan (-A).
Discovers network hops and route latency between scanner and target host.
"""

from __future__ import annotations

import asyncio
import platform
import re
import subprocess
from typing import List, Dict, Optional


class TracerouteRunner:
    """Executes network route tracing to target host."""

    @staticmethod
    async def run(target_ip: str, max_hops: int = 15, timeout: float = 12.0) -> List[Dict[str, str]]:
        """
        Runs traceroute/tracert asynchronously against target_ip.
        Returns a list of dicts: [{"hop": "1", "ip": "...", "rtt": "..."}, ...]
        """
        hops: List[Dict[str, str]] = []
        is_windows = platform.system().lower() == "windows"

        if is_windows:
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "500", target_ip]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", target_ip]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode("utf-8", errors="ignore")

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue

                # Windows tracert format: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
                # Linux traceroute format: " 1  192.168.1.1  0.450 ms  0.410 ms"
                parts = line.split()
                if parts and parts[0].isdigit():
                    hop_num = parts[0]
                    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if ip_match:
                        hop_ip = ip_match.group(1)
                    elif "*" in line or "Request timed out" in line:
                        hop_ip = "* (Timed out)"
                    else:
                        hop_ip = parts[-1]

                    # Extract average or first RTT if available
                    rtt_match = re.search(r"(\d+(?:\.\d+)?\s*ms|<1\s*ms)", line)
                    rtt = rtt_match.group(1) if rtt_match else "*"

                    hops.append({
                        "hop": hop_num,
                        "ip": hop_ip,
                        "rtt": rtt
                    })

                    # If we reached target, stop tracking further
                    if hop_ip == target_ip:
                        break

        except (asyncio.TimeoutError, FileNotFoundError, PermissionError, OSError):
            pass

        return hops
