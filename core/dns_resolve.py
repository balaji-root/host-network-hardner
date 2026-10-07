"""
Phase 2: DNS Resolution module for Host & Network Hardener.
Resolves DNS records (A, AAAA, MX, NS, TXT) and caches results in SQLite.
"""

from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional
import dns.resolver

from db import Database, get_timestamp


class DNSResolver:
    """DNS Resolver with SQLite caching support."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        clean = target.strip()
        for flag in ("-A", "--aggressive", "-F", "--full", "-u", "--udp"):
            clean = clean.replace(flag, "").strip()
        try:
            ipaddress.ip_address(clean)
            return True
        except ValueError:
            return False

    def resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve a domain name to its primary IPv4 address."""
        domain = domain.strip()
        for flag in ("-A", "--aggressive", "-F", "--full", "-u", "--udp"):
            domain = domain.replace(flag, "").strip()
        if "://" in domain:
            from urllib.parse import urlparse
            parsed = urlparse(domain)
            domain = parsed.hostname or domain
        elif "/" in domain:
            parts = domain.split("/", 1)
            if not parts[1].isdigit():
                domain = parts[0]
        domain = domain.strip().rstrip("/")

        if self.is_ip(domain):
            return domain

        # Check cache first
        cached = self._get_cached(domain, "A")
        if cached:
            return cached[0]

        # Query DNS
        try:
            answers = dns.resolver.resolve(domain, "A")
            ip = str(answers[0])
            self._save_cache(domain, "A", ip)
            return ip
        except Exception:
            # Fallback to socket.gethostbyname
            try:
                ip = socket.gethostbyname(domain)
                self._save_cache(domain, "A", ip)
                return ip
            except Exception:
                return None

    def resolve_all_records(self, domain: str) -> Dict[str, List[str]]:
        """Resolve A, AAAA, MX, NS, TXT records for a domain."""
        domain = domain.strip()
        if "://" in domain:
            from urllib.parse import urlparse
            parsed = urlparse(domain)
            domain = parsed.hostname or domain
        domain = domain.rstrip("/")

        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
        results: Dict[str, List[str]] = {}

        if self.is_ip(domain):
            results["A"] = [domain]
            return results

        for rtype in record_types:
            cached = self._get_cached(domain, rtype)
            if cached:
                results[rtype] = cached
                continue

            try:
                answers = dns.resolver.resolve(domain, rtype)
                vals = [str(ans) for ans in answers]
                for v in vals:
                    self._save_cache(domain, rtype, v)
                results[rtype] = vals
            except Exception:
                results[rtype] = []

        return results

    def _get_cached(self, query: str, rtype: str) -> List[str]:
        """Retrieve valid cached DNS records from database."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM dns_cache WHERE query = ? AND record_type = ?",
                (query.lower(), rtype.upper())
            )
            rows = cursor.fetchall()
            return [row["value"] for row in rows]

    def _save_cache(self, query: str, rtype: str, value: str, ttl: int = 300) -> None:
        """Save a DNS query result into database cache."""
        now = get_timestamp()
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO dns_cache (query, record_type, value, ttl, cached_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(query, record_type, value) DO UPDATE SET
                    cached_at = excluded.cached_at
                """,
                (query.lower(), rtype.upper(), value, ttl, now)
            )
