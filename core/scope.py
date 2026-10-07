"""
Scope validation engine for Host & Network Hardener.
Strict safety gate that validates targets against scope.yaml before any network operations.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml

from core.models import ScopeConfig


class ScopeViolationError(Exception):
    """Raised when a target or action violates the configured scope."""
    pass


def clean_target_spec(target: Any) -> str:
    """Sanitize target string by stripping URL schemes, paths, trailing flags (-A), and spaces."""
    if not target:
        return ""
    s = str(target).strip()
    for flag in ("-A", "--aggressive", "-F", "--full", "-u", "--udp"):
        s = s.replace(flag, "").strip()
    if "://" in s:
        from urllib.parse import urlparse
        parsed = urlparse(s)
        s = parsed.hostname or s
    elif "/" in s:
        parts = s.split("/", 1)
        if not parts[1].isdigit():
            s = parts[0]
    return s.strip().rstrip("/")


class ScopeValidator:
    """Validates targets and scan parameters against scope configuration."""

    def __init__(
        self,
        config_path: Optional[Union[str, Path]] = None,
        raw_config: Optional[Dict[str, Any]] = None,
        db: Optional[Any] = None
    ):
        self.config_path: Optional[Path] = None
        self.db = db

        if raw_config is not None:
            self.config = self._parse_config_dict(raw_config)
        elif config_path is not None:
            self.config_path = Path(config_path)
            self.config = self._load_from_yaml(self.config_path)
        else:
            default_path = Path("config/scope.yaml")
            if default_path.exists():
                self.config_path = default_path
                self.config = self._load_from_yaml(default_path)
            else:
                self.config = ScopeConfig()

        # If DB provided or default DB exists, load any additional scope targets
        if self.db:
            self.sync_with_db(self.db)

        self._allowed_ip_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._allowed_hosts: set[str] = set()
        self._excluded_ip_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._excluded_hosts: set[str] = set()

        self._compile_rules()

    def sync_with_db(self, db: Any) -> None:
        """Merge scope targets stored in database into memory."""
        try:
            db_targets = db.get_scope_targets()
            for row in db_targets:
                target = str(row["target"]).strip()
                ttype = row.get("target_type", "allowed")
                if ttype == "allowed" and target not in self.config.allowed_targets:
                    self.config.allowed_targets.append(target)
                elif ttype == "excluded" and target not in self.config.excluded_targets:
                    self.config.excluded_targets.append(target)
        except Exception:
            pass

    def add_target(
        self,
        target: str,
        target_type: str = "allowed",
        persist: bool = True,
        db: Optional[Any] = None
    ) -> bool:
        """
        Add a target (IP, CIDR, or hostname/domain) to scope.
        Optionally persists to scope.yaml and SQLite database.
        """
        target_str = clean_target_spec(target)
        if not target_str:
            return False

        target_list = self.config.allowed_targets if target_type == "allowed" else self.config.excluded_targets
        opposite_list = self.config.excluded_targets if target_type == "allowed" else self.config.allowed_targets

        # Remove from opposite list if present
        if target_str in opposite_list:
            opposite_list.remove(target_str)

        # Add to target list if not already present
        if target_str not in target_list:
            target_list.append(target_str)

        self._compile_rules()

        # Persist to YAML file
        if persist and self.config_path:
            self.save_to_yaml(self.config_path)

        # Persist to DB
        active_db = db or self.db
        if active_db:
            try:
                active_db.add_scope_target(target_str, target_type)
            except Exception:
                pass

        return True

    def remove_target(
        self,
        target: str,
        target_type: str = "allowed",
        persist: bool = True,
        db: Optional[Any] = None
    ) -> bool:
        """
        Remove a target from allowed or excluded scope.
        Optionally persists removal to scope.yaml and SQLite database.
        """
        target_str = clean_target_spec(target)
        if not target_str:
            return False

        target_list = self.config.allowed_targets if target_type == "allowed" else self.config.excluded_targets
        found = False

        if target_str in target_list:
            target_list.remove(target_str)
            found = True

        self._compile_rules()

        if found and persist and self.config_path:
            self.save_to_yaml(self.config_path)

        active_db = db or self.db
        if active_db:
            try:
                active_db.remove_scope_target(target_str)
            except Exception:
                pass

        return found

    def add_allowed_target(self, target: str) -> None:
        """Dynamically authorize a target at runtime (backwards-compatible)."""
        self.add_target(target, target_type="allowed", persist=False)

    def save_to_yaml(self, path: Optional[Union[str, Path]] = None) -> None:
        """Serialize current scope configuration back to YAML file."""
        target_path = Path(path) if path else self.config_path
        if not target_path:
            target_path = Path("config/scope.yaml")

        data = {
            "allowed_targets": self.config.allowed_targets,
            "excluded_targets": self.config.excluded_targets,
            "max_rate_per_sec": self.config.max_rate_per_sec,
            "scan_window": self.config.scan_window,
        }

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def _load_from_yaml(self, path: Path) -> ScopeConfig:
        if not path.exists():
            raise FileNotFoundError(f"Scope configuration file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return self._parse_config_dict(data)

    def _parse_config_dict(self, data: Dict[str, Any]) -> ScopeConfig:
        return ScopeConfig(
            allowed_targets=list(data.get("allowed_targets", [])),
            excluded_targets=list(data.get("excluded_targets", [])),
            max_rate_per_sec=int(data.get("max_rate_per_sec", 50)),
            scan_window=str(data.get("scan_window", "00:00-23:59")),
        )

    def _compile_rules(self) -> None:
        """Pre-parse IP networks and hostnames for high-speed matching."""
        self._allowed_ip_networks.clear()
        self._allowed_hosts.clear()
        self._excluded_ip_networks.clear()
        self._excluded_hosts.clear()

        for target in self.config.allowed_targets:
            target_clean = clean_target_spec(target)
            if not target_clean:
                continue
            try:
                # Attempt to parse as single IP or CIDR (strict=False permits single IP as /32 or /128)
                net = ipaddress.ip_network(target_clean, strict=False)
                self._allowed_ip_networks.append(net)
            except ValueError:
                self._allowed_hosts.add(target_clean.lower())

        for target in self.config.excluded_targets:
            target_clean = clean_target_spec(target)
            if not target_clean:
                continue
            try:
                net = ipaddress.ip_network(target_clean, strict=False)
                self._excluded_ip_networks.append(net)
            except ValueError:
                self._excluded_hosts.add(target_clean.lower())

    def _is_ip_matched(
        self, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]
    ) -> bool:
        for net in networks:
            if ip_obj in net:
                return True
        return False

    def _is_host_matched(self, hostname: str, host_set: set[str]) -> bool:
        normalized = hostname.lower().strip()
        if normalized in host_set:
            return True
        # Check wildcard subdomains if defined like *.domain.com or .domain.com
        for pattern in host_set:
            if pattern.startswith("*.") and normalized.endswith(pattern[1:]):
                return True
            if pattern.startswith(".") and normalized.endswith(pattern):
                return True
        return False

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        """
        Check whether a target is permitted under current scope rules.
        Returns (is_allowed, reason).
        Strictly zero network requests are made.
        """
        target_str = clean_target_spec(target)
        if not target_str:
            return False, "Target is empty"

        target_ip: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None
        try:
            target_ip = ipaddress.ip_address(target_str)
        except ValueError:
            target_ip = None

        # 1. Check exclusions first (exclusions always take absolute priority)
        if target_ip is not None:
            if self._is_ip_matched(target_ip, self._excluded_ip_networks):
                return False, f"Target IP '{target_str}' is explicitly excluded in scope configuration"
        else:
            if self._is_host_matched(target_str, self._excluded_hosts):
                return False, f"Target hostname '{target_str}' is explicitly excluded in scope configuration"

        # 2. Check allowed targets
        if target_ip is not None:
            if self._is_ip_matched(target_ip, self._allowed_ip_networks):
                return True, f"Target IP '{target_str}' matches authorized scope"
            return False, f"Target IP '{target_str}' is not in authorized scope"
        else:
            if self._is_host_matched(target_str, self._allowed_hosts):
                return True, f"Target hostname '{target_str}' matches authorized scope"
            return False, f"Target hostname '{target_str}' is not in authorized scope"

    def is_in_scan_window(self, check_time: Optional[datetime] = None) -> tuple[bool, str]:
        """Check if current time falls within configured scan_window (HH:MM-HH:MM)."""
        window = self.config.scan_window.strip()
        if not window or window == "*" or window == "all":
            return True, "Scan window is unrestricted"

        try:
            start_str, end_str = window.split("-")
            start_h, start_m = map(int, start_str.split(":"))
            end_h, end_m = map(int, end_str.split(":"))
            start_t = time(start_h, start_m)
            end_t = time(end_h, end_m)
        except Exception as e:
            return False, f"Invalid scan_window format '{window}': {e}"

        current_t = (check_time or datetime.now()).time()

        if start_t <= end_t:
            in_window = start_t <= current_t <= end_t
        else:
            # Spans midnight (e.g. 22:00-04:00)
            in_window = current_t >= start_t or current_t <= end_t

        if in_window:
            return True, f"Current time {current_t.strftime('%H:%M')} is within scan window {window}"
        return False, f"Current time {current_t.strftime('%H:%M')} is outside allowed scan window {window}"

    def enforce_scope(self, target: str, check_time: Optional[datetime] = None) -> None:
        """
        Enforce safety gate. Raises ScopeViolationError if target is out-of-scope
        or outside scan window.
        """
        # Time window check
        window_ok, window_msg = self.is_in_scan_window(check_time)
        if not window_ok:
            raise ScopeViolationError(f"Scan aborted by safety gate: {window_msg}")

        # Target scope check
        scope_ok, scope_msg = self.is_in_scope(target)
        if not scope_ok:
            raise ScopeViolationError(f"Target not authorized: {scope_msg}")
