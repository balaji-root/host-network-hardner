"""
CLI entrypoint for Host & Network Hardener.
Supports interactive target prompts, full 65,535 port scanning for TCP, top UDP port scanning,
ICMP host discovery, service banner enumeration, and SQLite persistence.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
import click

from core.dns_resolve import DNSResolver
from core.discovery import HostDiscovery
from core.models import PortInfo, Finding
from core.scanner import (
    AsyncPortScanner, parse_port_spec, COMMON_UDP_PORTS,
    get_service_name, SECURITY_RELEVANT_PORTS
)
from core.scope import ScopeValidator, ScopeViolationError
from core.enumerate import ServiceEnumerator
from core.os_fingerprint import OSFingerprinter
from core.checks import CheckRunner
from core.reporter import PDFReportGenerator
from core.traceroute import TracerouteRunner
from db import Database


@click.command()
@click.argument("target_arg", required=False, default=None, metavar="[TARGET]")
@click.option(
    "--target", "-t",
    required=False,
    default=None,
    help="Target host, IP, or domain to validate/scan."
)
@click.option(
    "--aggressive", "-A",
    is_flag=True,
    default=False,
    help="Enable aggressive scan (Nmap-style -A): OS detection, version probing, security checks, and traceroute."
)
@click.option(
    "--ports", "-p",
    required=False,
    default=None,
    help="Ports to scan (e.g., '80,443', '1-1024', '1-65535'). Default: all 65,535 TCP ports."
)
@click.option(
    "--full/--no-full", "-F",
    default=True,
    help="Perform full TCP scan across all 65,535 ports (default: enabled)."
)
@click.option(
    "--udp/--no-udp", "-u",
    default=True,
    help="Include top UDP port scanning alongside TCP (default: enabled)."
)
@click.option(
    "--config", "-c",
    default="config/scope.yaml",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to scope configuration YAML."
)
@click.option(
    "--check-scope-only",
    is_flag=True,
    default=False,
    help="Only perform Phase 1 scope validation and exit."
)
@click.option(
    "--concurrency",
    default=250,
    type=int,
    help="Max concurrent async connection workers (default: 250 for full scans)."
)
@click.option(
    "--show-filtered",
    is_flag=True,
    default=False,
    help="Display non-responding / filtered ports table (default: False, only verified open ports shown)."
)
@click.option(
    "--add-target", "-a",
    type=str,
    default=None,
    help="Add IP, CIDR range, or domain to authorized scope (saved to YAML & DB)."
)
@click.option(
    "--remove-target", "-r",
    type=str,
    default=None,
    help="Remove an IP, CIDR range, or domain from authorized scope."
)
@click.option(
    "--list-scope", "-l",
    is_flag=True,
    default=False,
    help="List all authorized and excluded scope targets from YAML and database."
)
@click.option(
    "--list-scans", "-s",
    is_flag=True,
    default=False,
    help="List all historical scans and hosts stored in SQLite database."
)
@click.option(
    "--delete-scan",
    type=str,
    default=None,
    help="Delete a specific target host and its scan history from database."
)
@click.option(
    "--clear-db",
    is_flag=True,
    default=False,
    help="Clear all previous scan results, hosts, ports, and findings from database."
)
@click.option(
    "--pdf", "-o",
    type=str,
    default=None,
    help="Custom path or filename for generated PDF security report (saved in reports/ by default)."
)
@click.option(
    "--no-pdf",
    is_flag=True,
    default=False,
    help="Disable automatic PDF security report generation."
)
@click.option(
    "--export-pdf",
    type=str,
    default=None,
    help="Generate a PDF report for a previously scanned host in SQLite database."
)
def main(
    target_arg: Optional[str],
    target: Optional[str],
    aggressive: bool,
    ports: Optional[str],
    full: bool,
    udp: bool,
    config: Path,
    check_scope_only: bool,
    concurrency: int,
    show_filtered: bool,
    add_target: Optional[str],
    remove_target: Optional[str],
    list_scope: bool,
    list_scans: bool,
    delete_scan: Optional[str],
    clear_db: bool,
    pdf: Optional[str],
    no_pdf: bool,
    export_pdf: Optional[str],
) -> None:
    """Host & Network Hardener"""
    click.secho("==================================================", fg="cyan", bold=True)
    click.secho("    Host & Network Hardener", fg="cyan", bold=True)
    click.secho("==================================================", fg="cyan", bold=True)

    # 1. Initialize DB & Scope Validator
    db = Database()
    validator = ScopeValidator(config_path=config, db=db)

    # Handle Exporting PDF from database
    if export_pdf:
        reporter = PDFReportGenerator()
        pdf_path = reporter.export_from_db(db, export_pdf, output_path=pdf)
        if pdf_path:
            click.secho(f"\n[+] PDF Security Report generated successfully for '{export_pdf}':", fg="green", bold=True)
            click.secho(f"    -> {pdf_path.resolve()}", fg="cyan", bold=True)
        else:
            click.secho(f"[-] Host '{export_pdf}' not found in scan database.", fg="yellow", bold=True)
        return

    # Handle Scope Management: Add Target
    if add_target:
        validator.add_target(add_target, target_type="allowed", persist=True, db=db)
        click.secho(f"[+] Successfully added '{add_target}' to authorized scope in config/scope.yaml and database.", fg="green", bold=True)
        return

    # Handle Scope Management: Remove Target
    if remove_target:
        removed = validator.remove_target(remove_target, target_type="allowed", persist=True, db=db)
        if removed:
            click.secho(f"[+] Successfully removed '{remove_target}' from authorized scope.", fg="green", bold=True)
        else:
            click.secho(f"[-] Target '{remove_target}' was not found in authorized scope.", fg="yellow", bold=True)
        return

    # Handle Scope Management: List Scope Targets
    if list_scope:
        click.secho("\nAUTHORIZED & CONFIGURED SCOPE TARGETS:", fg="magenta", bold=True)
        click.echo("=" * 60)
        click.secho("  Allowed Targets (Authorized for scanning):", fg="green", bold=True)
        for t in validator.config.allowed_targets:
            click.echo(f"    - {t}")
        if validator.config.excluded_targets:
            click.secho("\n  Excluded Targets (Explicitly Blacklisted):", fg="red", bold=True)
            for t in validator.config.excluded_targets:
                click.echo(f"    - {t}")
        click.echo("-" * 60)
        click.echo(f"  Max Rate Limit : {validator.config.max_rate_per_sec} packets/sec")
        click.echo(f"  Scan Window    : {validator.config.scan_window}")
        click.echo("=" * 60 + "\n")
        return

    # Handle Database Storage: List Scanned Hosts
    if list_scans:
        scans = db.get_hosts_summary()
        click.secho("\nHISTORICAL SCAN DATABASE (scan_results.db):", fg="magenta", bold=True)
        click.echo("=" * 80)
        if scans:
            click.secho(f"  {'TARGET':<24} {'PRIMARY IP':<16} {'STATUS':<8} {'PORTS':<7} {'FINDINGS':<10} {'LAST SCANNED'}", fg="cyan", bold=True)
            click.echo("  " + "-" * 76)
            for s in scans:
                last_scanned = (s.get("updated_at") or "")[:19].replace("T", " ")
                click.echo(f"  {s['target']:<24} {(s.get('ip') or 'N/A'):<16} {s['status']:<8} {s['open_ports_count']:<7} {s['findings_count']:<10} {last_scanned}")
        else:
            click.echo("  [*] No scan records found in database.")
        click.echo("=" * 80 + "\n")
        return

    # Handle Database Storage: Delete Specific Target
    if delete_scan:
        deleted = db.delete_host(delete_scan)
        if deleted:
            click.secho(f"[+] Successfully purged all scan data for '{delete_scan}' from database.", fg="green", bold=True)
        else:
            click.secho(f"[-] No records found for '{delete_scan}' in database.", fg="yellow", bold=True)
        return

    # Handle Database Storage: Clear All Scans
    if clear_db:
        if click.confirm(click.style("[?] Are you sure you want to clear all scan history from the database?", fg="red", bold=True), default=False):
            stats = db.clear_all_scans()
            click.secho(f"[+] Database purged: {stats['hosts_cleared']} host(s), {stats['ports_cleared']} port(s), {stats['findings_cleared']} finding(s) removed.", fg="green", bold=True)
        else:
            click.echo("[*] Database purge cancelled.")
        return

    # Resolve target from positional argument or --target/-t option
    effective_target = target or target_arg
    raw_input_target: str = effective_target.strip() if effective_target and effective_target.strip() else ""
    if not raw_input_target:
        prompt_val = click.prompt(
            click.style("[?] Enter target IP, domain, or subnet to scan", fg="yellow", bold=True),
            type=str
        )
        raw_input_target = str(prompt_val).strip()

    if not raw_input_target:
        click.secho("[-] Error: Target cannot be empty.", fg="red", bold=True)
        sys.exit(1)

    # Automatically parse and strip flags if user entered them in prompt or string (e.g. '45.33.32.156 -A')
    tokens = raw_input_target.split()
    clean_tokens = []
    for token in tokens:
        if token in ("-A", "--aggressive"):
            aggressive = True
        elif token in ("-F", "--full"):
            full = True
        elif token in ("-u", "--udp"):
            udp = True
        elif token.startswith("-p"):
            ports = token[2:] if len(token) > 2 else ports
        else:
            clean_tokens.append(token)

    cleaned_str = " ".join(clean_tokens).strip()

    # Strip URL schemes (http://, https://) and paths/trailing slashes
    if "://" in cleaned_str:
        from urllib.parse import urlparse
        parsed = urlparse(cleaned_str)
        cleaned_str = parsed.hostname or cleaned_str
    elif "/" in cleaned_str:
        parts = cleaned_str.split("/", 1)
        if not parts[1].isdigit():
            cleaned_str = parts[0]

    resolved_target: str = cleaned_str.strip().rstrip("/")

    if not resolved_target:
        click.secho("[-] Error: Target cannot be empty.", fg="red", bold=True)
        sys.exit(1)

    if aggressive:
        click.secho(
            "\n[!] AGGRESSIVE SCAN (-A) ENABLED: OS Detection + Deep Service Enumeration + Security Checks + Traceroute",
            fg="magenta", bold=True
        )

    # 2. Phase 1: Scope Validation Safety Gate
    click.echo(f"[*] Phase 1: Validating target '{resolved_target}' against scope...")
    try:
        validator.enforce_scope(resolved_target)
        click.secho(f"[+] Scope validation passed! Target '{resolved_target}' is authorized.", fg="green", bold=True)
    except ScopeViolationError as e:
        click.secho(f"[-] Notice: {e}", fg="yellow")
        if click.confirm(click.style(f"[?] Would you like to authorize and add '{resolved_target}' to scope now?", fg="yellow", bold=True), default=True):
            validator.add_target(resolved_target, target_type="allowed", persist=True, db=db)
            click.secho(f"[+] Target '{resolved_target}' added to authorized scope (config/scope.yaml & database)!", fg="green", bold=True)
        else:
            click.secho("[-] Target unauthorized. Aborting scan.", fg="red", bold=True)
            sys.exit(1)

    if check_scope_only:
        click.echo("[*] Scope check only requested. Exiting safely.")
        return

    # If user provided a specific port list via -p, override full flag
    is_full_scan = full if not ports else False

    # Run Async Pipeline
    asyncio.run(run_scan_pipeline(resolved_target, ports, is_full_scan, udp, concurrency, db, show_filtered, pdf, no_pdf, aggressive))


async def run_scan_pipeline(
    target: str,
    port_spec: Optional[str],
    full: bool,
    scan_udp: bool,
    concurrency: int,
    db: Database,
    show_filtered: bool = False,
    pdf_path: Optional[str] = None,
    no_pdf: bool = False,
    aggressive: bool = False
) -> None:
    start_time = time.time()

    # 3. Phase 2: DNS & Reconnaissance
    click.echo(f"\n[*] Phase 2: DNS & Reconnaissance for target '{target}'...")
    resolver = DNSResolver(db=db)
    target_ip = resolver.resolve_ip(target)

    if not target_ip:
        click.secho(f"[-] Could not resolve IP for domain '{target}'. Aborting scan.", fg="red", bold=True)
        return

    # Reverse DNS (PTR) Lookup
    ptr_record: Optional[str] = None
    try:
        ptr_record = socket.gethostbyaddr(target_ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        ptr_record = None

    # Resolve all DNS record types for domain targets
    dns_records = resolver.resolve_all_records(target)

    click.secho("-" * 75, fg="cyan")
    click.secho("RECONNAISSANCE SUMMARY", fg="magenta", bold=True)
    click.echo(f"  Target Host         : {target}")
    click.echo(f"  Resolved Primary IP : {target_ip}")
    if ptr_record:
        click.echo(f"  Reverse DNS (PTR)   : {ptr_record}")

    if dns_records:
        click.echo("  DNS Record Details  :")
        for rtype, values in dns_records.items():
            if values:
                val_str = ", ".join(values)
                click.echo(f"    - {rtype:<5}: {val_str}")
    click.secho("-" * 75, fg="cyan")

    # 4. Phase 3: Host Discovery (ICMP + TCP)
    click.echo(f"\n[*] Phase 3: Host Discovery (ICMP Echo Ping + TCP probes on {target_ip})...")
    discovery = HostDiscovery()
    is_live, discovery_method = await discovery.is_host_live(target_ip)

    if not is_live:
        click.secho(f"[-] Target {target_ip} appears DOWN/unreachable ({discovery_method}). Aborting scan.", fg="yellow", bold=True)
        return

    click.secho(f"[+] Host {target_ip} is LIVE! (Detected via {discovery_method})", fg="green", bold=True)

    # Aggressive Scan Phase: Traceroute (Nmap-style -A hop analysis)
    traceroute_hops: List[dict] = []
    if aggressive:
        click.echo(f"\n[*] Phase 3b: Traceroute [Aggressive -A] probing route to {target_ip}...")
        click.secho("-" * 75, fg="cyan")
        traceroute_hops = await TracerouteRunner.run(target_ip)
        if traceroute_hops:
            click.secho(f"  {'HOP':<6} {'RTT':<12} {'IP ADDRESS'}", fg="magenta", bold=True)
            click.echo("  " + "-" * 45)
            for h in traceroute_hops:
                click.echo(f"  {h['hop']:<6} {h['rtt']:<12} {h['ip']}")
            click.echo("-" * 45)
        else:
            click.echo("  [*] Traceroute hop tracing complete (target reached or hops filtered).")

    # 5. Phase 4: Async Port Scanning (TCP & UDP)
    port_list = parse_port_spec(port_spec, full=full)
    total_ports = len(port_list)
    scan_mode_label = f"ALL {total_ports:,} PORTS (1-65535)" if full or total_ports == 65535 else f"{total_ports} ports"

    click.echo(f"\n[*] Phase 4: Async TCP Scanning target {target_ip} ({scan_mode_label}, concurrency={concurrency})...")
    click.secho("-" * 75, fg="cyan")

    open_tcp_ports: List[PortInfo] = []
    filtered_tcp_ports: List[PortInfo] = []
    all_tcp_ports: List[PortInfo] = []   # every port seen (for Nmap-style table)
    closed_tcp_count = 0
    filtered_tcp_count = 0
    scanned_tcp_count = 0

    def on_tcp_port_scanned(pinfo: PortInfo) -> None:
        nonlocal closed_tcp_count, filtered_tcp_count, scanned_tcp_count
        scanned_tcp_count += 1
        all_tcp_ports.append(pinfo)
        if pinfo.state == "open":
            open_tcp_ports.append(pinfo)
            click.secho(
                f"[+] PORT {pinfo.port:<5}/tcp  OPEN     "
                f"(Service: {pinfo.service or 'unknown'})",
                fg="green", bold=True
            )
        elif pinfo.state == "closed":
            closed_tcp_count += 1
        else:
            filtered_tcp_count += 1
            filtered_tcp_ports.append(pinfo)
            # Only print filtered ports in real time if:
            # - Port is security-relevant / high-value service (e.g. SSH, FTP, RDP, SMB)
            # - User explicitly targeted a specific port list (e.g. -p 22, total_ports <= 50)
            # - User explicitly requested --show-filtered
            # This prevents printing 1,000+ unassigned random filtered ports which causes terminal lag.
            is_high_value = (pinfo.port in SECURITY_RELEVANT_PORTS)
            is_targeted = (total_ports <= 50)
            if is_high_value or is_targeted or show_filtered:
                click.secho(
                    f"[-] PORT {pinfo.port:<5}/tcp  FILTERED (Service: {pinfo.service or 'unknown'} | Reason: {pinfo.reason})",
                    fg="yellow"
                )

        # Periodic live progress updates
        step = 5000 if total_ports > 10000 else 500
        if total_ports >= step and (scanned_tcp_count % step == 0 or scanned_tcp_count == total_ports):
            percent = (scanned_tcp_count / total_ports) * 100
            click.secho(
                f"[*] Progress: {scanned_tcp_count:,}/{total_ports:,} TCP ports scanned ({percent:.1f}%) | "
                f"Open: {len(open_tcp_ports)} | Filtered: {filtered_tcp_count:,} | Closed: {closed_tcp_count:,}",
                fg="cyan"
            )

    scanner = AsyncPortScanner(concurrency=concurrency, timeout=0.45, db=db)
    await scanner.scan_target(
        target=target,
        target_ip=target_ip,
        ports=port_list,
        protocol="tcp",
        on_port_scanned=on_tcp_port_scanned
    )

    open_udp_ports: List[PortInfo] = []
    filtered_udp_ports: List[PortInfo] = []
    udp_ports: List[int] = []
    if scan_udp:
        # Limit UDP scan to top used ports (COMMON_UDP_PORTS) unless custom port list specified
        udp_ports = COMMON_UDP_PORTS if (full or not port_spec) else port_list
        total_udp = len(udp_ports)
        click.echo(f"\n[*] Async UDP Probing target {target_ip} ({total_udp:,} top UDP ports)...")
        click.secho("-" * 75, fg="cyan")

        scanned_udp_count = 0

        def on_udp_port_scanned(pinfo: PortInfo) -> None:
            nonlocal scanned_udp_count
            scanned_udp_count += 1
            if pinfo.state == "open":
                open_udp_ports.append(pinfo)
                click.secho(f"[+] PORT {pinfo.port:<5}/udp OPEN    (Service: {pinfo.service or 'unknown'})", fg="green", bold=True)
            elif pinfo.state in ("filtered", "open|filtered"):
                filtered_udp_ports.append(pinfo)
                is_high_val = pinfo.port in (53, 67, 68, 69, 123, 161, 500, 1194, 5353)
                if is_high_val or total_udp <= 20 or show_filtered:
                    click.secho(
                        f"[-] PORT {pinfo.port:<5}/udp FILTERED (Service: {pinfo.service or 'unknown'} | Reason: {pinfo.reason})",
                        fg="yellow"
                    )

        await scanner.scan_target(
            target=target,
            target_ip=target_ip,
            ports=udp_ports,
            protocol="udp",
            on_port_scanned=on_udp_port_scanned
        )

    # 6. Phase 5: Service Enumeration & Banner Grabbing
    all_open_ports = open_tcp_ports + open_udp_ports
    host_id = db.upsert_host(target=target, ip=target_ip, status="live")

    if open_tcp_ports:
        click.echo(f"\n[*] Phase 5: Service Enumeration on {len(open_tcp_ports)} open TCP port(s)...")
        enumerator = ServiceEnumerator(db=db)
        enum_sem = asyncio.Semaphore(10)

        async def _enumerate_single_port(pinfo: PortInfo) -> PortInfo:
            async with enum_sem:
                await enumerator.enumerate_port(target_ip, pinfo)
                desc = pinfo.version_info or pinfo.banner or "Service active"
                click.secho(
                    f"    [+] Port {pinfo.port:<5}/tcp -> Identified Service: {pinfo.service or 'unknown'} ({desc})",
                    fg="green", bold=True
                )
                db.upsert_port(
                    host_id=host_id,
                    port=pinfo.port,
                    protocol="tcp",
                    state="open",
                    service=pinfo.service,
                    banner=pinfo.banner
                )
                return pinfo

        await asyncio.gather(*[_enumerate_single_port(p) for p in open_tcp_ports])

    if open_udp_ports:
        click.echo(f"\n[*] Phase 5 (UDP): Service Enumeration on {len(open_udp_ports)} open UDP port(s)...")
        for pinfo in open_udp_ports:
            if not pinfo.service or pinfo.service == "unknown":
                pinfo.service = get_service_name(pinfo.port, "udp")
            desc = pinfo.banner or "UDP service active"
            click.secho(
                f"    [+] Port {pinfo.port:<5}/udp -> Identified Service: {pinfo.service or 'unknown'} ({desc})",
                fg="green", bold=True
            )
            db.upsert_port(
                host_id=host_id,
                port=pinfo.port,
                protocol="udp",
                state=pinfo.state,
                service=pinfo.service,
                banner=pinfo.banner
            )

    # 7. Phase 6: OS Fingerprinting
    click.echo(f"\n[*] Phase 6: OS Fingerprinting target {target_ip}...")
    fingerprinter = OSFingerprinter()
    os_guess, os_confidence = fingerprinter.fingerprint(all_open_ports)
    if os_guess != "Unknown OS":
        click.secho(f"[+] OS Fingerprint: {os_guess} (Confidence: {os_confidence * 100:.0f}%)", fg="green", bold=True)
    else:
        click.echo("[*] OS Fingerprint: Unknown / Inconclusive")

    # Update host record with OS guess
    db.upsert_host(target=target, ip=target_ip, status="live", os_guess=os_guess, os_confidence=os_confidence)

    # 8. Phase 7: Pluggable Security Checks
    click.echo(f"\n[*] Phase 7: Executing Security & Vulnerability Checks...")
    runner = CheckRunner()
    findings: List[Finding] = runner.run_all(target_ip, all_open_ports)

    if findings:
        click.secho(f"[!] Discovered {len(findings)} Security Finding(s)!", fg="yellow", bold=True)
        for finding in findings:
            db.add_finding(
                host_id=host_id,
                port=finding.port,
                check_name=finding.check_name,
                title=finding.title,
                severity=finding.severity.value,
                impact=finding.impact,
                likelihood=finding.likelihood,
                risk_score=finding.risk_score,
                description=finding.description,
                remediation=finding.remediation,
                raw_evidence=finding.raw_evidence
            )
    else:
        click.secho("[+] No security vulnerabilities detected by automated checks.", fg="green")

    # Terminal Scan Results Summary
    elapsed = time.time() - start_time
    click.secho("-" * 75, fg="cyan")
    click.secho(f"\n[=] SCAN RESULTS SUMMARY for {target} ({target_ip})", fg="magenta", bold=True)
    if aggressive:
        click.secho("    Scan Profile        : AGGRESSIVE (-A)", fg="magenta", bold=True)
        if traceroute_hops:
            click.echo(f"    Traceroute Hops     : {len(traceroute_hops)} hop(s) recorded")
    click.echo(f"    Host Status         : Live ({discovery_method})")
    click.echo(f"    OS Guess            : {os_guess}" + (f" ({os_confidence * 100:.0f}% confidence)" if os_guess != "Unknown OS" else ""))
    click.echo(f"    Total Ports Scanned : {total_ports:,} TCP" + (f" + {len(udp_ports):,} UDP" if scan_udp else ""))
    click.secho(f"    Open TCP Ports      : {len(open_tcp_ports)}", fg="green" if open_tcp_ports else "white", bold=True)
    if scan_udp:
        click.secho(f"    Open UDP Ports      : {len(open_udp_ports)}", fg="green" if open_udp_ports else "white", bold=True)
    click.echo(f"    Closed TCP Ports    : {closed_tcp_count:,}")
    click.echo(f"    Filtered TCP Ports  : {filtered_tcp_count:,}")
    click.secho(f"    Security Findings   : {len(findings)}", fg="yellow" if findings else "white", bold=True)
    click.echo(f"    Scan Duration       : {elapsed:.2f} seconds\n")

    # ================================================================
    # PORT SCAN RESULTS (Legit & Clean, Nmap-standard)
    # ================================================================
    # Only verified OPEN ports that actually responded are displayed.
    # Non-responding (filtered or closed) ports are cleanly summarized.
    # ================================================================

    open_rows: List[PortInfo] = [p for p in open_tcp_ports if p.state == "open"]
    non_responding_count: int = total_ports - len(open_rows)

    click.secho("\n" + "=" * 80, fg="cyan")
    click.secho("  PORT SCAN RESULTS", fg="cyan", bold=True)
    click.secho("=" * 80, fg="cyan")

    if open_rows:
        click.secho(f"\n  {'PORT':<14} {'STATE':<10} {'SERVICE':<18} {'VERSION / BANNER'}",
                    fg="green", bold=True)
        click.secho("  " + "-" * 76, fg="green")
        for p in sorted(open_rows, key=lambda x: x.port):
            port_col = f"{p.port}/tcp"
            ver_text = (p.version_info or p.banner or "Service active").replace("\n", " ").replace("\r", "")[:38]
            click.secho(
                f"  {port_col:<14} {'open':<10} {(p.service or 'unknown'):<18} {ver_text}",
                fg="green", bold=True
            )
    else:
        click.secho("\n  [*] No open TCP ports detected.", fg="yellow")

    # Dedicated FILTERED TCP PORTS Table with Diagnostic Reason / Probe Evidence
    display_filtered = [
        p for p in filtered_tcp_ports
        if show_filtered or total_ports <= 50 or (p.port in SECURITY_RELEVANT_PORTS)
    ]
    if display_filtered:
        click.secho(f"\n  FILTERED TCP PORTS (FIREWALL / PROBE DIAGNOSIS):", fg="yellow", bold=True)
        click.secho(f"  {'PORT':<14} {'STATE':<10} {'SERVICE':<16} {'WHY & HOW FILTERED (DIAGNOSTIC EVIDENCE)'}",
                    fg="yellow", bold=True)
        click.secho("  " + "-" * 105, fg="yellow")
        for p in sorted(display_filtered, key=lambda x: x.port):
            port_col = f"{p.port}/tcp"
            reason_text = (p.reason or p.raw_evidence or "No response (probe dropped by firewall)").replace("\n", " ")[:80]
            click.secho(
                f"  {port_col:<14} {'filtered':<10} {(p.service or 'unknown'):<16} {reason_text}",
                fg="yellow"
            )
        unshown_filtered = filtered_tcp_count - len(display_filtered)
        if unshown_filtered > 0:
            click.secho(f"  [*] Plus {unshown_filtered:,} other unassigned filtered ports. Use --show-filtered to display all.", fg="cyan")

    # Clean Nmap-style summary for all non-responding / filtered / closed ports
    if non_responding_count > 0:
        click.secho(
            f"\n  [*] Note: {closed_tcp_count:,} closed TCP ports (RST), {filtered_tcp_count:,} filtered TCP ports (silent drop / firewall).",
            fg="cyan"
        )

    # Optional: if user explicitly requested --show-filtered, display filtered security ports with pentest hints
    if show_filtered:
        filtered_rows = [p for p in all_tcp_ports if p.state == "filtered" and p.port in SECURITY_RELEVANT_PORTS]
        if filtered_rows:
            click.secho(f"\n  FILTERED SECURITY-RELEVANT PORTS (PENTEST AUDIT):", fg="magenta", bold=True)
            click.secho(f"  {'PORT':<14} {'STATE':<12} {'SERVICE':<18} {'EXPLOIT POTENTIAL'}",
                        fg="magenta", bold=True)
            click.secho("  " + "-" * 76, fg="magenta")
            for p in sorted(filtered_rows, key=lambda x: x.port):
                port_col = f"{p.port}/tcp"
                svc_name, hint = SECURITY_RELEVANT_PORTS[p.port]
                click.secho(f"  {port_col:<14} {'filtered':<12} {svc_name:<18} {hint}", fg="yellow")

    click.secho("\n" + "=" * 80, fg="cyan")

    # ── UDP open ports ───────────────────────────────────────────────
    if open_udp_ports:
        click.secho("\nUDP OPEN PORTS:", fg="yellow", bold=True)
        click.echo(f"{'PORT':<14} {'STATE':<12} {'SERVICE':<20} {'BANNER'}")
        click.echo("-" * 60)
        for pinfo in sorted(open_udp_ports, key=lambda p: p.port):
            port_proto = f"{pinfo.port}/udp"
            svc = pinfo.service or get_service_name(pinfo.port, "udp")
            banner = (pinfo.banner or "").replace("\n", " ")[:30]
            click.secho(
                f"{port_proto:<14} {pinfo.state:<12} {svc:<20} {banner}",
                fg="green", bold=True
            )
        click.echo("-" * 60)

    if findings:
        click.echo("")
        click.secho("SECURITY FINDINGS SUMMARY TABLE:", fg="yellow", bold=True)
        click.echo(f"{'SEVERITY':<10} {'RISK':<6} {'PORT':<8} {'CHECK':<20} {'TITLE'}")
        click.echo("-" * 75)
        for f in findings:
            port_str = str(f.port) if f.port else "N/A"
            sev_color = "red" if f.severity.value in ("High", "Critical") else ("yellow" if f.severity.value == "Medium" else "white")
            click.secho(f"{f.severity.value:<10} {f.risk_score:<6} {port_str:<8} {f.check_name:<20} {f.title}", fg=sev_color)
        click.echo("-" * 75)

        click.echo("")
        click.secho("DETAILED VULNERABILITY ASSESSMENT CARDS:", fg="magenta", bold=True)
        click.echo("=" * 75)
        for f in findings:
            port_str = f"Port {f.port}" if f.port else "Host-level"
            sev_fg = "red" if f.severity.value in ("High", "Critical") else "yellow"
            click.secho(f"[{f.severity.value.upper()}] Risk Score: {f.risk_score}/25 | {port_str} | {f.title}", fg=sev_fg, bold=True)
            click.echo(f"  Check Module : {f.check_name}")
            click.echo(f"  Impact       : {f.impact}/5 | Likelihood: {f.likelihood}/5")
            click.echo(f"  Description  : {f.description}")
            if f.remediation:
                click.secho(f"  Remediation  : {f.remediation}", fg="cyan")
            if f.raw_evidence:
                click.echo(f"  Evidence     : {f.raw_evidence}")
            click.echo("-" * 75)

    click.secho("\n[+] Scan results & detailed findings stored successfully in SQLite database (scan_results.db).", fg="green", bold=True)

    # 9. Phase 8: Professional Executive & Technical PDF Report Generation
    if not no_pdf:
        reporter = PDFReportGenerator()
        report_data = {
            "target": target,
            "target_ip": target_ip,
            "ptr_record": ptr_record,
            "status": "live",
            "discovery_method": discovery_method,
            "os_guess": os_guess,
            "os_confidence": os_confidence,
            "dns_records": dns_records,
            "scope_status": "Authorized & Validated",
            "total_ports": total_ports,
            "open_ports": all_open_ports,
            "filtered_ports": filtered_tcp_ports,
            "closed_tcp_count": closed_tcp_count,
            "filtered_tcp_count": filtered_tcp_count,
            "duration": elapsed,
            "scan_date": datetime.now(timezone.utc).strftime("%B %d, %Y - %H:%M UTC"),
            "findings": findings,
        }
        try:
            pdf_file = reporter.generate_report(report_data, output_path=pdf_path)
            click.secho(f"\n[+] Professional PDF Security Report generated successfully:", fg="green", bold=True)
            click.secho(f"    -> {pdf_file.resolve()}", fg="cyan", bold=True)
        except Exception as e:
            click.secho(f"\n[-] Note: Failed to generate PDF report: {e}", fg="yellow")


if __name__ == "__main__":
    main()

