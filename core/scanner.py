"""
Phase 4: Async Port Scanner Engine for Host & Network Hardener.
Uses asyncio + Bounded Concurrency to scan TCP and UDP ports efficiently across all 65,535 ports.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Callable, Dict, List, Optional, Tuple

from core.models import PortInfo
from db import Database

# Common default TCP ports
COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
    3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 27017
]

# Common default UDP ports
COMMON_UDP_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1194, 1900, 4500, 5353
]

# ---------------------------------------------------------------------------
# Nmap-aligned well-known service name table.
# Used to label ports regardless of open/closed/filtered state, exactly as
# Nmap does (e.g. 21→ftp, 3389→ms-wbt-server, 143→imap).
# Keys are (port, protocol) tuples; protocol is 'tcp' or 'udp'.
# ---------------------------------------------------------------------------
WELL_KNOWN_SERVICES: Dict[Tuple[int, str], str] = {
    # TCP services
    (1,    "tcp"): "tcpmux",
    (7,    "tcp"): "echo",
    (9,    "tcp"): "discard",
    (11,   "tcp"): "systat",
    (13,   "tcp"): "daytime",
    (17,   "tcp"): "qotd",
    (19,   "tcp"): "chargen",
    (20,   "tcp"): "ftp-data",
    (21,   "tcp"): "ftp",
    (22,   "tcp"): "ssh",
    (23,   "tcp"): "telnet",
    (25,   "tcp"): "smtp",
    (37,   "tcp"): "time",
    (43,   "tcp"): "whois",
    (53,   "tcp"): "domain",
    (67,   "tcp"): "dhcps",
    (68,   "tcp"): "dhcpc",
    (69,   "tcp"): "tftp",
    (70,   "tcp"): "gopher",
    (79,   "tcp"): "finger",
    (80,   "tcp"): "http",
    (88,   "tcp"): "kerberos-sec",
    (102,  "tcp"): "iso-tsap",
    (110,  "tcp"): "pop3",
    (111,  "tcp"): "rpcbind",
    (113,  "tcp"): "ident",
    (119,  "tcp"): "nntp",
    (123,  "tcp"): "ntp",
    (135,  "tcp"): "msrpc",
    (137,  "tcp"): "netbios-ns",
    (138,  "tcp"): "netbios-dgm",
    (139,  "tcp"): "netbios-ssn",
    (143,  "tcp"): "imap",
    (161,  "tcp"): "snmp",
    (162,  "tcp"): "snmptrap",
    (179,  "tcp"): "bgp",
    (194,  "tcp"): "irc",
    (389,  "tcp"): "ldap",
    (443,  "tcp"): "https",
    (445,  "tcp"): "microsoft-ds",
    (464,  "tcp"): "kpasswd5",
    (465,  "tcp"): "smtps",
    (500,  "tcp"): "isakmp",
    (512,  "tcp"): "exec",
    (513,  "tcp"): "login",
    (514,  "tcp"): "shell",
    (515,  "tcp"): "printer",
    (543,  "tcp"): "klogin",
    (544,  "tcp"): "kshell",
    (587,  "tcp"): "submission",
    (593,  "tcp"): "http-rpc-epmap",
    (631,  "tcp"): "ipp",
    (636,  "tcp"): "ldapssl",
    (691,  "tcp"): "resvc",
    (902,  "tcp"): "iss-realsecure",
    (990,  "tcp"): "ftps",
    (992,  "tcp"): "telnets",
    (993,  "tcp"): "imaps",
    (995,  "tcp"): "pop3s",
    (1025, "tcp"): "NFS-or-IIS",
    (1080, "tcp"): "socks",
    (1099, "tcp"): "rmiregistry",
    (1194, "tcp"): "openvpn",
    (1241, "tcp"): "nessus",
    (1311, "tcp"): "dell-omsa",
    (1337, "tcp"): "waste",
    (1352, "tcp"): "lotusnotes",
    (1433, "tcp"): "ms-sql-s",
    (1434, "tcp"): "ms-sql-m",
    (1521, "tcp"): "oracle",
    (1524, "tcp"): "ingreslock",
    (1604, "tcp"): "icabrowser",
    (1720, "tcp"): "h323hostcall",
    (1723, "tcp"): "pptp",
    (1761, "tcp"): "landesk-rc",
    (1812, "tcp"): "radius",
    (1813, "tcp"): "radius-acct",
    (1883, "tcp"): "mqtt",
    (1900, "tcp"): "upnp",
    (1935, "tcp"): "rtmp",
    (2000, "tcp"): "cisco-sccp",
    (2049, "tcp"): "nfs",
    (2082, "tcp"): "infowave",
    (2083, "tcp"): "radsec",
    (2086, "tcp"): "cpanel",
    (2087, "tcp"): "cpanel-ssl",
    (2121, "tcp"): "proftp",
    (2181, "tcp"): "zookeeper",
    (2222, "tcp"): "ssh-alt",
    (2375, "tcp"): "docker",
    (2376, "tcp"): "docker-s",
    (2404, "tcp"): "iec-60870-5-104",
    (2483, "tcp"): "oracle-tcps",
    (2484, "tcp"): "oracle-tcps",
    (3000, "tcp"): "http-node",
    (3128, "tcp"): "squid-http",
    (3268, "tcp"): "globalcatLDAP",
    (3269, "tcp"): "globalcatLDAPssl",
    (3306, "tcp"): "mysql",
    (3389, "tcp"): "ms-wbt-server",
    (3632, "tcp"): "distcc",
    (3690, "tcp"): "svn",
    (4040, "tcp"): "spark-ui",
    (4369, "tcp"): "epmd",
    (4433, "tcp"): "https-alt",
    (4443, "tcp"): "https-alt",
    (4444, "tcp"): "metasploit",
    (4840, "tcp"): "opcua",
    (4843, "tcp"): "opcua-tls",
    (5000, "tcp"): "http-flask",
    (5001, "tcp"): "commplex-link",
    (5060, "tcp"): "sip",
    (5061, "tcp"): "sip-tls",
    (5222, "tcp"): "xmpp-client",
    (5269, "tcp"): "xmpp-server",
    (5432, "tcp"): "postgresql",
    (5555, "tcp"): "adb",
    (5601, "tcp"): "kibana",
    (5672, "tcp"): "rabbitmq",
    (5900, "tcp"): "vnc",
    (5901, "tcp"): "vnc-1",
    (5938, "tcp"): "teamviewer",
    (5984, "tcp"): "couchdb",
    (5985, "tcp"): "winrm-http",
    (5986, "tcp"): "winrm-https",
    (6000, "tcp"): "x11",
    (6379, "tcp"): "redis",
    (6443, "tcp"): "kubernetes-api",
    (6666, "tcp"): "irc",
    (6667, "tcp"): "irc",
    (6881, "tcp"): "bittorrent-tracker",
    (7000, "tcp"): "cassandra",
    (7001, "tcp"): "weblogic",
    (7077, "tcp"): "spark",
    (7443, "tcp"): "oracleas-https",
    (7687, "tcp"): "neo4j-bolt",
    (8000, "tcp"): "http-alt",
    (8008, "tcp"): "http-alt",
    (8009, "tcp"): "ajp13",
    (8080, "tcp"): "http-proxy",
    (8081, "tcp"): "http-alt",
    (8082, "tcp"): "http-alt",
    (8086, "tcp"): "influxdb",
    (8088, "tcp"): "http-alt",
    (8090, "tcp"): "http-alt",
    (8180, "tcp"): "http-tomcat",
    (8181, "tcp"): "http-alt",
    (8200, "tcp"): "vault",
    (8300, "tcp"): "consul",
    (8443, "tcp"): "https-alt",
    (8500, "tcp"): "consul-ui",
    (8787, "tcp"): "drb",
    (8888, "tcp"): "http-alt",
    (9000, "tcp"): "http-alt",
    (9001, "tcp"): "tor-orport",
    (9042, "tcp"): "cassandra",
    (9090, "tcp"): "http-alt",
    (9092, "tcp"): "kafka",
    (9100, "tcp"): "jetdirect",
    (9200, "tcp"): "elasticsearch",
    (9300, "tcp"): "elasticsearch-cluster",
    (9418, "tcp"): "git",
    (9443, "tcp"): "https-alt",
    (9929, "tcp"): "nping-echo",
    (9999, "tcp"): "abyss",
    (10000, "tcp"): "webmin",
    (10001, "tcp"): "scp-config",
    (10250, "tcp"): "kubelet",
    (10255, "tcp"): "kubelet-readonly",
    (11211, "tcp"): "memcached",
    (12345, "tcp"): "netbus",
    (15672, "tcp"): "rabbitmq-mgmt",
    (20034, "tcp"): "netbus",
    (25565, "tcp"): "minecraft",
    (27017, "tcp"): "mongodb",
    (27018, "tcp"): "mongos",
    (27374, "tcp"): "subseven",
    (28017, "tcp"): "mongodb-web",
    (31337, "tcp"): "Elite",
    (32768, "tcp"): "filenet-tms",
    (49152, "tcp"): "msrpc",
    (49153, "tcp"): "msrpc",
    (49154, "tcp"): "msrpc",
    (50000, "tcp"): "ibm-db2",
    (50070, "tcp"): "hadoop-namenode",
    (60000, "tcp"): "mosh",
    (65535, "tcp"): "rcmd",
    # UDP services
    (53,   "udp"): "domain",
    (67,   "udp"): "dhcps",
    (68,   "udp"): "dhcpc",
    (69,   "udp"): "tftp",
    (123,  "udp"): "ntp",
    (137,  "udp"): "netbios-ns",
    (138,  "udp"): "netbios-dgm",
    (161,  "udp"): "snmp",
    (162,  "udp"): "snmptrap",
    (500,  "udp"): "isakmp",
    (514,  "udp"): "syslog",
    (520,  "udp"): "router",
    (1194, "udp"): "openvpn",
    (1900, "udp"): "upnp",
    (4500, "udp"): "nat-t-ike",
    (5353, "udp"): "mdns",
    (5355, "udp"): "llmnr",
}

# ---------------------------------------------------------------------------
# Security-relevant ports: filtered ports worth flagging for pentesters.
# Only includes universally high-value targets found in real-world attacks.
# Format: port -> (service_name, short_exploit_hint)
# ---------------------------------------------------------------------------
SECURITY_RELEVANT_PORTS: Dict[int, tuple] = {
    # Remote Access & Shells
    21:    ("ftp",           "Anon login / brute-force"),
    22:    ("ssh",           "Brute-force / weak ciphers"),
    23:    ("telnet",        "Plaintext creds / MITM"),
    512:   ("exec",          "Rexec unauthenticated / weak auth command execution"),
    513:   ("login",         "Rlogin rhosts trust relationship abuse"),
    514:   ("shell",         "Rsh remote shell execution"),
    1524:  ("ingreslock",    "Ingreslock root bindshell backdoor"),
    2121:  ("proftp",        "ProFTPD alternate / backdoor / weak creds"),
    3389:  ("ms-wbt-server", "BlueKeep / DejaBlue / brute-force"),
    5900:  ("vnc",           "No-auth / weak password"),
    5985:  ("winrm",         "Lateral movement / brute-force"),
    # Web & Application Servers
    80:    ("http",          "Web vulns / dir traversal"),
    443:   ("https",         "TLS misconfig / web vulns"),
    8009:  ("ajp13",         "Ghostcat AJP file read/RCE (CVE-2020-1938)"),
    8080:  ("http-proxy",    "Open proxy / SSRF / admin panels"),
    8180:  ("http-tomcat",   "Tomcat manager default creds / WAR upload RCE"),
    8443:  ("https-alt",     "Admin panels / web vulns"),
    # Mail
    25:    ("smtp",          "Relay abuse / user enum"),
    110:   ("pop3",          "Plaintext creds / brute-force"),
    143:   ("imap",          "Plaintext creds / brute-force"),
    # Windows / File Sharing
    139:   ("netbios-ssn",   "EternalBlue attack path"),
    445:   ("microsoft-ds",  "EternalBlue / PetitPotam / relay"),
    2049:  ("nfs",           "Unauth mount / file exfil"),
    # Databases
    1433:  ("ms-sql-s",      "xp_cmdshell RCE / brute-force"),
    1521:  ("oracle",        "TNS poison / brute-force"),
    3306:  ("mysql",         "Unauth / UDF RCE / brute-force"),
    5432:  ("postgresql",    "COPY RCE / brute-force"),
    6379:  ("redis",         "Unauth RCE / config write"),
    27017: ("mongod",        "Unauth data access"),
    # Infrastructure & Chat
    161:   ("snmp",          "Community string brute / info leak"),
    2375:  ("docker",        "Unencrypted Docker daemon — RCE"),
    6443:  ("kube-api",      "Kubernetes API — cluster takeover"),
    6667:  ("irc",           "UnrealIRCd backdoor / unauthenticated command execution"),
    # Backdoors / Special / Recon
    1337:  ("waste",         "Elite / hacker port / waste"),
    3632:  ("distcc",        "distcc unauthenticated command execution RCE (CVE-2004-2687)"),
    4444:  ("metasploit",    "Metasploit default listener / shell"),
    8787:  ("drb",           "Ruby DRb unauthenticated remote code execution"),
    9929:  ("nping-echo",    "Nmap Nping echo service"),
    12345: ("netbus",        "NetBus backdoor trojan"),
    31337: ("Elite",         "Elite backdoor / remote root shell"),
}


# ---------------------------------------------------------------------------
# Top 1,000 Main TCP Ports:
# Standard ports 1-1024 plus all registered well-known service & security ports.
# Aligned with Nmap default scan behavior (fast, thorough, avoids scanning
# 64,000 unassigned ephemeral ports unless --full is requested).
# ---------------------------------------------------------------------------
TOP_1000_TCP_PORTS: List[int] = sorted(list(set(
    list(range(1, 1025)) +
    [p for p, proto in WELL_KNOWN_SERVICES.keys() if proto == "tcp"] +
    list(SECURITY_RELEVANT_PORTS.keys())
)))


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """
    Return the well-known service name for a port/protocol pair.

    Resolution order:
      1. WELL_KNOWN_SERVICES lookup table (Nmap-aligned, authoritative)
      2. socket.getservbyport() OS fallback
      3. 'unknown' if neither source has a name
    """
    key = (port, protocol.lower())
    if key in WELL_KNOWN_SERVICES:
        return WELL_KNOWN_SERVICES[key]
    try:
        return socket.getservbyport(port, protocol.lower())
    except OSError:
        return "unknown"


def parse_port_spec(port_spec: Optional[str] = None, full: bool = False) -> List[int]:
    """
    Parse port specification string into a list of integers.
    Supports formats:
    - full=True or "full" or "1-65535" or None/empty -> all 65,535 ports
    - "80,443,8080"
    - "1-1024"
    - "80,100-200,8080"
    """
    if full or (port_spec and port_spec.lower() in ("full", "all", "1-65535")) or not port_spec:
        return list(range(1, 65536))

    ports = set()
    parts = port_spec.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_str, end_str = part.split("-", 1)
                start_p = max(1, int(start_str.strip()))
                end_p = min(65535, int(end_str.strip()))
                for p in range(start_p, end_p + 1):
                    ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue

    return sorted(list(ports)) if ports else list(range(1, 65536))


class AsyncPortScanner:
    """Async TCP & UDP Port Scanner with bounded concurrency."""

    def __init__(
        self,
        concurrency: int = 250,
        timeout: float = 0.5,
        retries: int = 1,
        db: Optional[Database] = None
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.db = db or Database()
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_target(
        self,
        target: str,
        target_ip: str,
        ports: List[int],
        protocol: str = "tcp",
        on_port_scanned: Optional[Callable[[PortInfo], None]] = None
    ) -> List[PortInfo]:
        """
        Scan target IP across specified TCP or UDP ports concurrently.
        Saves results to SQLite DB.
        """
        host_id = self.db.upsert_host(target=target, ip=target_ip, status="live")
        results: List[PortInfo] = []

        batch_size = 2000
        for i in range(0, len(ports), batch_size):
            chunk = ports[i : i + batch_size]
            if protocol.lower() == "udp":
                tasks = [
                    self._scan_single_udp_port(target_ip, port, host_id, on_port_scanned)
                    for port in chunk
                ]
            else:
                tasks = [
                    self._scan_single_tcp_port(target_ip, port, host_id, on_port_scanned)
                    for port in chunk
                ]

            scanned_chunk = await asyncio.gather(*tasks, return_exceptions=True)

            for res in scanned_chunk:
                if isinstance(res, PortInfo):
                    results.append(res)

            # Brief pause between chunks allows the target's SYN backlog to recover
            if i + batch_size < len(ports):
                await asyncio.sleep(0.05)

        return results

    async def _scan_single_tcp_port(
        self,
        ip: str,
        port: int,
        host_id: int,
        on_port_scanned: Optional[Callable[[PortInfo], None]] = None
    ) -> PortInfo:
        """Scan a single TCP port with Semaphore rate limiting and retry on timeout."""
        async with self.semaphore:
            state = "closed"
            banner: Optional[str] = None
            service_name: str = get_service_name(port, "tcp")
            reason: Optional[str] = None
            last_err: Optional[Exception] = None

            attempts = 0
            max_attempts = max(1, self.retries + 1)

            while attempts < max_attempts:
                attempts += 1
                try:
                    conn = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                    state = "open"
                    reason = "TCP SYN-ACK received; 3-way handshake established"
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                    break
                except ConnectionRefusedError:
                    state = "closed"
                    reason = "RST packet received from host (connection refused)"
                    break
                except asyncio.TimeoutError as te:
                    state = "filtered"
                    last_err = te
                    if attempts < max_attempts:
                        await asyncio.sleep(0.05)
                except OSError as oe:
                    err_code = getattr(oe, 'winerror', None) or getattr(oe, 'errno', None)
                    if err_code in (10061, 111):  # WSAECONNREFUSED / ECONNREFUSED
                        state = "closed"
                        reason = "RST packet received from host (connection refused)"
                        break
                    state = "filtered"
                    last_err = oe
                    if attempts < max_attempts:
                        await asyncio.sleep(0.05)

            if state == "filtered":
                if isinstance(last_err, asyncio.TimeoutError):
                    reason = (
                        f"No response / SYN dropped after {attempts} probe(s) "
                        f"(timeout={self.timeout}s) - silent packet drop "
                        f"(host firewall or packet filter)"
                    )
                elif isinstance(last_err, OSError):
                    err_code = getattr(last_err, 'winerror', None) or getattr(last_err, 'errno', None)
                    if err_code in (10060, 110):
                        reason = (
                            f"Connection timed out ({err_code}) after {attempts} probe(s) - "
                            f"no SYN-ACK/RST received (firewall DROP rule)"
                        )
                    elif err_code in (10065, 113):
                        reason = (
                            f"Host unreachable ({err_code}) - ICMP destination unreachable / "
                            f"communication administratively prohibited"
                        )
                    elif err_code in (10051, 101):
                        reason = f"Network unreachable ({err_code}) - route or gateway blocked probe"
                    else:
                        reason = f"Network error ({err_code or last_err}) after {attempts} probe(s) - probe dropped"
                else:
                    reason = f"No response received after {attempts} probe(s) (packet filtered)"

            port_info = PortInfo(
                port=port,
                protocol="tcp",
                state=state,
                service=service_name,
                banner=banner,
                reason=reason,
                raw_evidence=reason
            )

            # Persist port state to DB if open or if filtered & relevant
            if state == "open" or (state == "filtered" and (port in SECURITY_RELEVANT_PORTS or service_name != "unknown")):
                self.db.upsert_port(
                    host_id=host_id,
                    port=port,
                    protocol="tcp",
                    state=state,
                    service=service_name,
                    banner=banner,
                    raw_evidence=reason
                )

            if on_port_scanned:
                on_port_scanned(port_info)

            return port_info

    async def _scan_single_udp_port(
        self,
        ip: str,
        port: int,
        host_id: int,
        on_port_scanned: Optional[Callable[[PortInfo], None]] = None
    ) -> PortInfo:
        """Scan a single UDP port with Semaphore rate limiting using UDP socket probes."""
        async with self.semaphore:
            state = "open|filtered"
            banner: Optional[str] = None
            reason: Optional[str] = None

            # Resolve service name for every UDP port regardless of state.
            service_name: str = get_service_name(port, "udp")

            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)

            try:
                # Service probe payload (e.g., DNS header for port 53, empty bytes for others)
                payload = b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00" if port == 53 else b"\x00" * 8
                await loop.sock_sendto(sock, payload, (ip, port))

                try:
                    data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout=self.timeout)
                    state = "open"
                    reason = "UDP response datagram received from service"
                    banner = data.decode("utf-8", errors="ignore").strip()[:100]
                except (asyncio.TimeoutError, OSError):
                    state = "open|filtered"
                    reason = (
                        f"No UDP or ICMP response received within {self.timeout}s timeout "
                        f"(application silent or packet filtered by firewall)"
                    )

            except ConnectionRefusedError:
                state = "closed"
                reason = "ICMP Port Unreachable received (port is closed)"
            except Exception as e:
                state = "closed"
                reason = f"UDP probe error: {e}"
            finally:
                sock.close()

            port_info = PortInfo(
                port=port,
                protocol="udp",
                state=state,
                service=service_name,
                banner=banner,
                reason=reason,
                raw_evidence=reason
            )

            if state == "open" or (state in ("filtered", "open|filtered") and (port in (53, 67, 68, 69, 123, 137, 138, 161, 500, 1194, 5353) or service_name != "unknown")):
                self.db.upsert_port(
                    host_id=host_id,
                    port=port,
                    protocol="udp",
                    state=state,
                    service=service_name,
                    banner=banner,
                    raw_evidence=reason
                )

            if on_port_scanned:
                on_port_scanned(port_info)

            return port_info
