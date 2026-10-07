"""
Database module for Host & Network Hardener.
Handles SQLite schema creation, migrations, and database operations.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional, Union

DEFAULT_DB_PATH = Path("scan_results.db")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    ip TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    os_guess TEXT,
    os_confidence REAL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(target, ip)
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'closed',
    service TEXT,
    banner TEXT,
    raw_evidence TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER,
    check_name TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    impact INTEGER NOT NULL,
    likelihood INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT,
    raw_evidence TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dns_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER NOT NULL DEFAULT 300,
    cached_at TEXT NOT NULL,
    UNIQUE(query, record_type, value)
);

CREATE TABLE IF NOT EXISTS scope_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL UNIQUE,
    target_type TEXT NOT NULL DEFAULT 'allowed',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
CREATE INDEX IF NOT EXISTS idx_dns_cache_query ON dns_cache(query, record_type);
CREATE INDEX IF NOT EXISTS idx_scope_targets ON scope_targets(target);
"""


def get_timestamp() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class Database:
    """SQLite Database manager for scan results."""

    def __init__(self, db_path: Union[str, Path] = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for SQLite database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize database tables and schema."""
        if self.db_path.parent and not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)

    def upsert_host(
        self,
        target: str,
        ip: Optional[str] = None,
        status: str = "unknown",
        os_guess: Optional[str] = None,
        os_confidence: Optional[float] = None,
    ) -> int:
        """Insert or update a host record and return its id."""
        now = get_timestamp()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO hosts (target, ip, status, os_guess, os_confidence, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target, ip) DO UPDATE SET
                    status = excluded.status,
                    os_guess = COALESCE(excluded.os_guess, hosts.os_guess),
                    os_confidence = COALESCE(excluded.os_confidence, hosts.os_confidence),
                    updated_at = excluded.updated_at
                RETURNING id
                """,
                (target, ip or "", status, os_guess, os_confidence, now, now),
            )
            row = cursor.fetchone()
            return row["id"]

    def upsert_port(
        self,
        host_id: int,
        port: int,
        protocol: str = "tcp",
        state: str = "open",
        service: Optional[str] = None,
        banner: Optional[str] = None,
        raw_evidence: Optional[str] = None,
    ) -> int:
        """Insert or update a port record and return its id."""
        now = get_timestamp()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO ports (host_id, port, protocol, state, service, banner, raw_evidence, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                    state = excluded.state,
                    service = COALESCE(excluded.service, ports.service),
                    banner = COALESCE(excluded.banner, ports.banner),
                    raw_evidence = COALESCE(excluded.raw_evidence, ports.raw_evidence),
                    updated_at = excluded.updated_at
                RETURNING id
                """,
                (host_id, port, protocol, state, service, banner, raw_evidence, now),
            )
            row = cursor.fetchone()
            return row["id"]

    def add_finding(
        self,
        host_id: int,
        check_name: str,
        title: str,
        severity: str,
        impact: int,
        likelihood: int,
        risk_score: int,
        description: str,
        port: Optional[int] = None,
        remediation: Optional[str] = None,
        raw_evidence: Optional[str] = None,
    ) -> int:
        """Insert a security finding and return its id."""
        now = get_timestamp()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO findings (
                    host_id, port, check_name, title, severity, impact, likelihood,
                    risk_score, description, remediation, raw_evidence, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
                """,
                (
                    host_id,
                    port,
                    check_name,
                    title,
                    severity,
                    impact,
                    likelihood,
                    risk_score,
                    description,
                    remediation,
                    raw_evidence,
                    now,
                ),
            )
            row = cursor.fetchone()
            return row["id"]

    def get_hosts(self) -> List[dict]:
        """Fetch all hosts."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hosts ORDER BY id ASC")
            return [dict(row) for row in cursor.fetchall()]

    def get_host_by_target(self, target_or_ip: str) -> Optional[dict]:
        """Fetch a specific host by target or IP."""
        target_clean = str(target_or_ip).strip()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM hosts WHERE target = ? OR ip = ? ORDER BY updated_at DESC LIMIT 1",
                (target_clean, target_clean)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_dns_records(self, query: str) -> Dict[str, List[str]]:
        """Fetch cached DNS records for a host query."""
        clean_q = str(query).strip().lower()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT record_type, value FROM dns_cache WHERE query = ?", (clean_q,))
            results: Dict[str, List[str]] = {}
            for row in cursor.fetchall():
                rtype = row["record_type"]
                val = row["value"]
                results.setdefault(rtype, []).append(val)
            return results

    def get_ports_for_host(self, host_id: int) -> List[dict]:
        """Fetch all scanned ports for a given host."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ports WHERE host_id = ? ORDER BY port ASC", (host_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_findings_for_host(self, host_id: int) -> List[dict]:
        """Fetch all findings for a given host."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE host_id = ? ORDER BY risk_score DESC", (host_id,))
            return [dict(row) for row in cursor.fetchall()]

    def add_scope_target(self, target: str, target_type: str = "allowed") -> int:
        """Insert or update an authorized/excluded scope target in the database."""
        now = get_timestamp()
        target_clean = str(target).strip()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scope_targets (target, target_type, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(target) DO UPDATE SET
                    target_type = excluded.target_type
                RETURNING id
                """,
                (target_clean, target_type, now)
            )
            row = cursor.fetchone()
            return row["id"]

    def remove_scope_target(self, target: str) -> bool:
        """Remove a target from the scope database table."""
        target_clean = str(target).strip()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scope_targets WHERE target = ?", (target_clean,))
            return cursor.rowcount > 0

    def get_scope_targets(self, target_type: Optional[str] = None) -> List[dict]:
        """Fetch scope targets from database, optionally filtered by type."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if target_type:
                cursor.execute("SELECT * FROM scope_targets WHERE target_type = ? ORDER BY id ASC", (target_type,))
            else:
                cursor.execute("SELECT * FROM scope_targets ORDER BY id ASC")
            return [dict(row) for row in cursor.fetchall()]

    def delete_host(self, target_or_ip: str) -> bool:
        """Delete a host record and its cascaded ports and findings by target or IP."""
        target_clean = str(target_or_ip).strip()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM hosts WHERE target = ? OR ip = ?", (target_clean, target_clean))
            return cursor.rowcount > 0

    def clear_all_scans(self) -> dict:
        """Purge all scan history, hosts, ports, findings, and cached DNS records."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM findings")
            findings_del = cursor.rowcount
            cursor.execute("DELETE FROM ports")
            ports_del = cursor.rowcount
            cursor.execute("DELETE FROM hosts")
            hosts_del = cursor.rowcount
            cursor.execute("DELETE FROM dns_cache")
            dns_del = cursor.rowcount
            return {
                "hosts_cleared": hosts_del,
                "ports_cleared": ports_del,
                "findings_cleared": findings_del,
                "dns_cache_cleared": dns_del,
            }

    def get_hosts_summary(self) -> List[dict]:
        """Fetch summary of all hosts stored in DB with open ports and finding counts."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT 
                    h.id,
                    h.target,
                    h.ip,
                    h.status,
                    h.os_guess,
                    h.created_at,
                    h.updated_at,
                    COUNT(DISTINCT p.id) as open_ports_count,
                    COUNT(DISTINCT f.id) as findings_count
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id AND p.state = 'open'
                LEFT JOIN findings f ON h.id = f.host_id
                GROUP BY h.id
                ORDER BY h.updated_at DESC
            """
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]

