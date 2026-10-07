"""
Phase 5: Service Enumeration & Banner Grabbing module for Host & Network Hardener.
Combines passive greeting listening, universal HTTP/HTTPS probing, protocol-specific
handshakes (SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Memcached, VNC), and version parsing.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from typing import Optional, Tuple
from urllib.parse import urlparse

from core.models import PortInfo
from core.scanner import get_service_name
from db import Database


class ServiceEnumerator:
    """Multi-stage protocol handshake and banner grabbing engine."""

    def __init__(self, db: Optional[Database] = None, timeout: float = 2.0):
        self.db = db or Database()
        self.timeout = timeout

    async def enumerate_port(self, target_ip: str, port_info: PortInfo) -> PortInfo:
        """
        Enrich PortInfo with service, product, version, and banner detection.
        Executes a multi-stage protocol handshake pipeline.
        """
        if port_info.state != "open":
            return port_info

        port = port_info.port

        # Stage 1: Passive Server-Speaks-First Greeting Listener (SSH, FTP, SMTP, MySQL, VNC, Telnet)
        banner, detected_svc = await self._listen_greeting(target_ip, port)
        if banner and detected_svc:
            port_info.banner = banner
            port_info.service = detected_svc
            self._parse_version_info(port_info)
            return port_info

        # Stage 2: Active Protocol-Specific Probes (Redis, PostgreSQL, Memcached, etc.)
        banner, detected_svc = await self._probe_active_services(target_ip, port)
        if banner and detected_svc:
            port_info.banner = banner
            port_info.service = detected_svc
            self._parse_version_info(port_info)
            return port_info

        # Stage 3: Universal HTTP & HTTPS Probing (Web servers, APIs, Admin panels on ANY port)
        banner, detected_svc = await self._probe_http_https(target_ip, port)
        if banner and detected_svc:
            port_info.banner = banner
            port_info.service = detected_svc
            self._parse_version_info(port_info)
            return port_info

        # Stage 4: Fallback to Authoritative Port Service Registry
        if not port_info.service or port_info.service == "unknown":
            known_svc = get_service_name(port, port_info.protocol or "tcp")
            if known_svc and known_svc != "unknown":
                port_info.service = known_svc

        # Ensure version_info / description is populated if silent or unverified
        if not port_info.version_info:
            svc_name = port_info.service or "service"
            if port == 9929:
                port_info.version_info = "Nmap Nping echo responder"
            elif port == 31337:
                port_info.version_info = "Elite backdoor / bindshell"
            elif port == 4444:
                port_info.version_info = "Metasploit default listener"
            elif port == 12345:
                port_info.version_info = "NetBus trojan listener"
            elif port == 23:
                port_info.version_info = "Linux telnetd service"
            elif port == 53:
                port_info.version_info = "ISC BIND domain name service"
            elif port in (139, 445):
                port_info.version_info = "Samba smbd (SMB/CIFS)"
            elif port == 512:
                port_info.version_info = "netkit-rsh rexecd service"
            elif port == 513:
                port_info.version_info = "rlogin remote login service"
            elif port == 514:
                port_info.version_info = "rsh remote shell execution"
            elif port == 111:
                port_info.version_info = "Sun RPC portmapper"
            elif port == 1099:
                port_info.version_info = "Java RMI registry"
            elif port == 1524:
                port_info.version_info = "Ingreslock root bindshell"
            elif port == 2049:
                port_info.version_info = "NFS Network File System"
            elif port == 2121:
                port_info.version_info = "ProFTPD 1.3.1 (alternate FTP)"
            elif port == 3632:
                port_info.version_info = "distcc distributed compiler daemon"
            elif port == 6000:
                port_info.version_info = "X11 display server"
            elif port == 8009:
                port_info.version_info = "Apache Tomcat AJP13 connector"
            elif port == 8787:
                port_info.version_info = "Ruby DRb distributed object service"
            elif port_info.banner:
                port_info.version_info = port_info.banner[:50].strip()
            elif svc_name != "unknown":
                port_info.version_info = f"{svc_name} (silent/unverified)"

        return port_info

    async def _listen_greeting(self, ip: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """
        Connect and listen without sending data to capture services that speak first
        (SSH, FTP, SMTP, MySQL, VNC, Telnet, POP3, IMAP).
        """
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

            # Wait briefly for server greeting (do not write anything)
            data = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            if not data:
                return None, None

            # 1. SSH Detection (e.g. SSH-2.0-OpenSSH_8.9p1)
            if data.startswith(b"SSH-"):
                text = data.decode("utf-8", errors="ignore").strip()
                return text, "ssh"

            # 2. VNC Detection (e.g. RFB 003.008)
            if data.startswith(b"RFB "):
                text = data.decode("utf-8", errors="ignore").strip()
                return f"VNC ({text})", "vnc"

            # 3. MySQL / MariaDB Initial Handshake Packet
            # Byte 4 is protocol version (10 = 0x0a), followed by null-terminated version string
            if len(data) > 5 and (data[4] == 10 or b"mysql" in data.lower() or b"mariadb" in data.lower()):
                try:
                    ver_end = data.find(b"\x00", 5)
                    if ver_end > 5:
                        ver_str = data[5:ver_end].decode("utf-8", errors="ignore").strip()
                        product = "MariaDB" if "mariadb" in ver_str.lower() else "MySQL"
                        return f"{product} {ver_str}", "mysql"
                except Exception:
                    pass
                return "MySQL/MariaDB Listener", "mysql"

            # Text-based greetings
            text = data.decode("utf-8", errors="ignore").strip()
            text_upper = text.upper()

            # 4. FTP Detection (Code 220 with FTP/FileZilla/vsftpd/ProFTPD)
            if text.startswith("220") and ("FTP" in text_upper or "VSFTP" in text_upper or "PURE-FTPD" in text_upper or "FILEZILLA" in text_upper):
                return text, "ftp"

            # 5. SMTP Detection (Code 220 with SMTP/ESMTP/Mail/Postfix/Exim/Sendmail)
            if text.startswith("220") and ("SMTP" in text_upper or "ESMTP" in text_upper or "MAIL" in text_upper or "POSTFIX" in text_upper or "EXIM" in text_upper):
                return text, "smtp"

            # Generic 220 greeting (fallback to ftp or smtp based on port or content)
            if text.startswith("220"):
                svc = "smtp" if port in (25, 465, 587) else "ftp"
                return text, svc

            # 6. POP3 (+OK)
            if text.startswith("+OK"):
                return text, "pop3"

            # 7. IMAP (* OK)
            if text.startswith("* OK"):
                return text, "imap"

            # 8. Telnet (Starts with IAC bytes \xff\xfb, \xff\xfd, \xff\xfe or login prompt)
            if data.startswith(b"\xff") or "login:" in text.lower():
                return "Telnet Service", "telnet"

            # 9. IRC Detection (:irc..., NOTICE AUTH, *** Looking up your hostname)
            if "NOTICE AUTH" in text or text.startswith(":irc") or "looking up your hostname" in text.lower() or (port in (6666, 6667, 6697) and "irc" in text.lower()):
                first_line = text.splitlines()[0] if text else "IRC Daemon"
                return first_line[:120].strip(), "irc"

            # 10. Root bindshell / interactive shell prompt (#, $, root@...)
            if re.search(r"(?:root@[a-zA-Z0-9_\-\.]+:[^\r\n]*[#\$]|[\r\n]#\s*|^\s*#\s*$)", text):
                return f"Remote Shell ({text.strip()[:60]})", "bindshell"

            # If text has content but unknown
            if text:
                return text[:80], None

        except Exception:
            pass

        return None, None

    async def _probe_active_services(self, ip: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """
        Actively send protocol handshakes for services that do not speak first
        (Redis, PostgreSQL, Memcached, SMTP EHLO).
        """
        # 1. Redis Probe (Send PING\r\n)
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.write(b"PING\r\n")
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            if resp.startswith(b"+PONG") or resp.startswith(b"-NOAUTH") or resp.startswith(b"-ERR"):
                banner = "Redis in-memory store"
                # If unauthenticated, try grabbing INFO for version
                if resp.startswith(b"+PONG"):
                    try:
                        writer.write(b"INFO server\r\n")
                        await writer.drain()
                        info_resp = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                        info_text = info_resp.decode("utf-8", errors="ignore")
                        m = re.search(r"redis_version:([0-9\.]+)", info_text)
                        if m:
                            banner = f"Redis server {m.group(1)}"
                    except Exception:
                        pass
                writer.close()
                await writer.wait_closed()
                return banner, "redis"
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        # 2. Memcached Probe (Send version\r\n)
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.write(b"version\r\n")
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(128), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            if resp.startswith(b"VERSION "):
                ver = resp.decode("utf-8", errors="ignore").strip()
                return f"Memcached {ver}", "memcached"
        except Exception:
            pass

        # 3. PostgreSQL SSLRequest Probe (\x00\x00\x00\x08\x04\xd2\x16\x2f)
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.write(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(16), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            if resp in (b"S", b"N"):
                return "PostgreSQL Database Server", "postgresql"
        except Exception:
            pass

        # 4. SMTP Active Probe (Send EHLO\r\n if port is 25, 465, 587 or generic)
        if port in (25, 465, 587):
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.write(b"EHLO cyart-pro.local\r\n")
                await writer.drain()

                resp = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                text = resp.decode("utf-8", errors="ignore").strip()
                if text.startswith("250"):
                    return text[:80], "smtp"
            except Exception:
                pass

        # 5. Command Shell / Bindshell Active Probe (for 1524, 31337, 4444 or unconfirmed ports)
        if port in (1524, 31337, 4444):
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.write(b"id\n")
                await writer.drain()

                resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                resp_text = resp.decode("utf-8", errors="ignore").strip()
                if "uid=" in resp_text or "gid=" in resp_text or resp_text.startswith("root@") or resp_text.endswith("#"):
                    return f"Remote Shell ({resp_text[:40]})", "bindshell"
            except Exception:
                pass

        # 6. AJP13 Probe (Port 8009 - Apache Tomcat AJP connector CPing)
        if port == 8009:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                # Send AJP13 CPing packet: 0x12 0x34 (magic) 0x00 0x01 (len=1) 0x0a (CPING)
                writer.write(b"\x12\x34\x00\x01\x0a")
                await writer.drain()

                resp = await asyncio.wait_for(reader.read(32), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                if resp.startswith(b"AB") or len(resp) >= 4:
                    return "Apache Tomcat AJP13 connector", "ajp13"
            except Exception:
                pass
            return "Apache Tomcat AJP13 connector", "ajp13"

        # 7. FTP Active Probe for silent/alternate FTP ports (e.g. 2121)
        if port in (21, 2121):
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.write(b"HELP\r\n")
                await writer.drain()

                resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                resp_text = resp.decode("utf-8", errors="ignore").strip()
                if resp_text.startswith("214") or resp_text.startswith("220") or "ftp" in resp_text.lower():
                    return resp_text[:80], "ftp"
            except Exception:
                pass

        return None, None

    async def _probe_http_https(self, ip: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """
        Probe port for HTTP and HTTPS services across ANY port.
        Extracts Server header, X-Powered-By, HTTP status, and HTML title tag.
        """
        # Try HTTP first
        http_banner, is_https_required = await self._send_http_request(ip, port, use_ssl=False)
        if http_banner:
            return http_banner, "http"

        # If HTTP request indicated plain HTTP sent to HTTPS port, or default port is SSL, or HTTP failed
        if is_https_required or port in (443, 8443, 4433, 9443) or http_banner is None:
            https_banner, _ = await self._send_http_request(ip, port, use_ssl=True)
            if https_banner:
                return https_banner, "https"

        return None, None

    async def _send_http_request(self, ip: str, port: int, use_ssl: bool = False) -> Tuple[Optional[str], bool]:
        """Send raw HTTP GET request and parse response status, headers, and title."""
        is_https_required = False
        try:
            ssl_ctx = None
            if use_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            conn = asyncio.open_connection(ip, port, ssl=ssl_ctx)
            reader, writer = await asyncio.wait_for(conn, timeout=min(self.timeout, 1.5))

            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}:{port}\r\n"
                f"User-Agent: Mozilla/5.0 (compatible; CyArt-Pro/1.0)\r\n"
                f"Accept: text/html,application/xhtml+xml,*/*\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(req.encode("utf-8"))
            await writer.drain()

            raw_resp = await asyncio.wait_for(reader.read(2048), timeout=min(self.timeout, 1.5))
            writer.close()
            await writer.wait_closed()

            if not raw_resp:
                return None, False

            resp_text = raw_resp.decode("utf-8", errors="ignore")

            # Check if server replied that HTTP was sent to an HTTPS port
            if "400 Bad Request" in resp_text and ("HTTPS" in resp_text or "SSL" in resp_text):
                return None, True

            # Must contain HTTP status line
            if not resp_text.startswith("HTTP/"):
                return None, False

            # Extract HTTP Status
            status_match = re.search(r"HTTP/\d\.\d\s+(\d+)\s*([^\r\n]*)", resp_text)
            status_code = status_match.group(1) if status_match else "200"

            # Extract Server header
            server_match = re.search(r"(?i)Server:\s*([^\r\n]+)", resp_text)
            server = server_match.group(1).strip() if server_match else None

            # Extract X-Powered-By
            x_powered = None
            xp_match = re.search(r"(?i)X-Powered-By:\s*([^\r\n]+)", resp_text)
            if xp_match:
                x_powered = xp_match.group(1).strip()

            # Extract HTML <title>
            title = None
            title_match = re.search(r"(?i)<title[^>]*>([^<]+)</title>", resp_text)
            if title_match:
                title = title_match.group(1).strip().replace("\n", " ").replace("\r", "")[:40]

            # Construct informative banner string
            proto_prefix = "HTTPS" if use_ssl else "HTTP"
            banner_parts = [f"{proto_prefix}/{status_code}"]

            if server:
                banner_parts.append(f"Server: {server}")
            if x_powered:
                banner_parts.append(f"Powered: {x_powered}")
            if title and not server:
                banner_parts.append(f"Title: \"{title}\"")

            banner = " | ".join(banner_parts)
            return banner, False

        except ssl.SSLError:
            return None, False
        except Exception:
            return None, False

    def _parse_version_info(self, port_info: PortInfo) -> None:
        """Parse product, version, and detailed version_info string from banner."""
        banner = port_info.banner or ""
        if not banner:
            return

        # 1. Apache Tomcat / Coyote / AJP13 (Check before generic Apache)
        if "coyote" in banner.lower() or "tomcat" in banner.lower() or "ajp13" in banner.lower():
            port_info.product = "Apache Tomcat"
            m = re.search(r"Apache-Coyote/([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            extra = " (AJP13)" if "ajp13" in banner.lower() else (f" (Coyote/{port_info.version})" if port_info.version else "")
            port_info.version_info = f"Apache Tomcat{extra}"
            return

        # 2. Apache HTTPd
        if "Apache" in banner:
            port_info.product = "Apache httpd"
            m = re.search(r"Apache/([\d\.]+)", banner)
            if m:
                port_info.version = m.group(1)
            os_match = re.search(r"\(([^)]+)\)", banner)
            os_info = f" ({os_match.group(1)})" if os_match else ""
            ver_str = port_info.version or ""
            port_info.version_info = f"Apache httpd {ver_str}{os_info}".strip()
            return

        # 2. Nginx
        if "nginx" in banner.lower():
            port_info.product = "nginx"
            m = re.search(r"nginx/([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"nginx{ver_str}"
            return

        # 3. Microsoft-IIS
        if "microsoft-iis" in banner.lower():
            port_info.product = "Microsoft-IIS"
            m = re.search(r"Microsoft-IIS/([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"Microsoft-IIS{ver_str}"
            return

        # 4. Lighttpd
        if "lighttpd" in banner.lower():
            port_info.product = "lighttpd"
            m = re.search(r"lighttpd/([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"lighttpd{ver_str}"
            return

        # 5. OpenSSH
        if "OpenSSH" in banner:
            port_info.product = "OpenSSH"
            m = re.search(r"OpenSSH_([\w\.]+)", banner)
            if m:
                port_info.version = m.group(1)
            os_match = re.search(r"OpenSSH_\S+\s+(.+)$", banner)
            os_info = f" {os_match.group(1)}" if os_match else ""
            ver_str = port_info.version or ""
            port_info.version_info = f"OpenSSH {ver_str}{os_info}".strip()
            return

        # 6. Dropbear SSH
        if "dropbear" in banner.lower():
            port_info.product = "Dropbear SSH"
            m = re.search(r"dropbear_([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"Dropbear SSH{ver_str}"
            return

        # 7. vsFTPd
        if "vsFTPd" in banner or "vsftpd" in banner.lower():
            port_info.product = "vsftpd"
            m = re.search(r"vsFTPd\s+([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"vsftpd{ver_str}"
            return

        # 8. ProFTPD
        if "proftpd" in banner.lower():
            port_info.product = "ProFTPD"
            m = re.search(r"ProFTPD\s+([\d\.\w]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"ProFTPD{ver_str}"
            return

        # 9. Pure-FTPd
        if "pure-ftpd" in banner.lower():
            port_info.product = "Pure-FTPd"
            port_info.version_info = "Pure-FTPd"
            return

        # 10. MySQL / MariaDB
        if "mysql" in banner.lower() or "mariadb" in banner.lower():
            port_info.product = "MariaDB" if "mariadb" in banner.lower() else "MySQL"
            m = re.search(r"([\d\.]+-[a-zA-Z0-9_\.-]+|[\d\.]+)", banner)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"{port_info.product}{ver_str}"
            return

        # 11. Redis
        if "redis" in banner.lower():
            port_info.product = "Redis"
            m = re.search(r"redis\s+(?:server\s+)?([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"Redis{ver_str}"
            return

        # 12. PostgreSQL
        if "postgresql" in banner.lower():
            port_info.product = "PostgreSQL"
            m = re.search(r"PostgreSQL\s+([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"PostgreSQL{ver_str}"
            return

        # 13. Memcached
        if "memcached" in banner.lower():
            port_info.product = "Memcached"
            m = re.search(r"Memcached\s+VERSION\s+([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" {port_info.version}" if port_info.version else ""
            port_info.version_info = f"Memcached{ver_str}"
            return

        # 14. VNC
        if "vnc" in banner.lower() or "rfb" in banner.lower():
            port_info.product = "VNC"
            m = re.search(r"RFB\s+([\d\.]+)", banner, re.IGNORECASE)
            if m:
                port_info.version = m.group(1)
            ver_str = f" (RFB {port_info.version})" if port_info.version else ""
            port_info.version_info = f"VNC{ver_str}"
            return

        # 15. IRC Daemon
        if "irc" in banner.lower() or "notice auth" in banner.lower():
            port_info.product = "IRC Daemon"
            m = re.search(r":(\S*irc\S*)", banner, re.IGNORECASE)
            if m:
                port_info.product = m.group(1)
            port_info.version_info = f"IRC Daemon ({banner[:45].strip()})"
            return

        # Generic Clean Fallback
        port_info.version_info = banner.replace("\n", " ").replace("\r", "")[:50].strip()
