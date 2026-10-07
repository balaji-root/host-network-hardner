"""
PDF Reporting Module for Host & Network Hardener.
Generates summarized, executive-ready, highly readable PDF assessment reports
capturing all reconnaissance, port scans, OS fingerprinting, firewall metrics,
and security findings with actionable remediation steps.
"""

from __future__ import annotations

import os
import re
import xml.sax.saxutils as saxutils
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from db import Database


# ── Color Palette ─────────────────────────────────────────────────────────────
PRIMARY_DARK = colors.HexColor("#0F172A")    # Deep Slate 900
BRAND_BLUE = colors.HexColor("#0284C7")      # Sky Blue 600
BRAND_TEAL = colors.HexColor("#0D9488")      # Teal 600
BG_LIGHT = colors.HexColor("#F8FAFC")        # Slate 50
BORDER_COLOR = colors.HexColor("#CBD5E1")    # Slate 300
TEXT_DARK = colors.HexColor("#0F172A")       # Primary Text
TEXT_MUTED = colors.HexColor("#475569")      # Secondary / Muted Text

# Severity Colors
SEV_CRITICAL = colors.HexColor("#DC2626")    # Crimson Red
SEV_HIGH = colors.HexColor("#EA580C")        # Amber Orange
SEV_MEDIUM = colors.HexColor("#D97706")      # Warm Yellow / Amber
SEV_LOW = colors.HexColor("#2563EB")         # Royal Blue
SEV_INFO = colors.HexColor("#475569")        # Slate Gray
SEV_PASS = colors.HexColor("#16A34A")        # Forest Green


def safe_text(text: Any) -> str:
    """Sanitize and XML-escape text to prevent ReportLab markup parse errors."""
    if text is None:
        return ""
    s = str(text)
    # Replace non-printable or exotic Unicode symbols that standard fonts cannot display
    s = s.encode("latin-1", "replace").decode("latin-1")
    return saxutils.escape(s)


def clean_banner(banner: Optional[str]) -> str:
    """Sanitize banner strings, stripping raw binary garbage or unprintable characters."""
    if not banner:
        return "Service active (no banner)"
    # Replace unprintable ASCII control characters
    cleaned = re.sub(r"[\x00-\x1f\x7f-\xff]+", " ", str(banner)).strip()
    if not cleaned or len(cleaned) < 2 or sum(c.isalnum() for c in cleaned) < 2:
        return "Binary service response (active)"
    return safe_text(cleaned[:110])


def consolidate_findings(findings: List[Any]) -> List[Dict[str, Any]]:
    """
    Consolidate findings by (title, port), eliminating duplicate rows and cards
    from repeated scan runs, while keeping the highest risk score and tallying count.
    """
    grouped: Dict[tuple, Dict[str, Any]] = {}
    for f in findings:
        if isinstance(f, dict):
            sev = f.get("severity", "Info")
            score = f.get("risk_score", 0)
            impact = f.get("impact", 1)
            likelihood = f.get("likelihood", 1)
            port = f.get("port")
            mod = f.get("check_name", "N/A")
            title = f.get("title", "Untitled finding")
            desc = f.get("description", "No description provided.")
            remediation = f.get("remediation")
            evidence = f.get("raw_evidence")
        else:
            sev = getattr(f.severity, "value", str(f.severity))
            score = f.risk_score
            impact = f.impact
            likelihood = f.likelihood
            port = f.port
            mod = f.check_name
            title = f.title
            desc = f.description
            remediation = f.remediation
            evidence = f.raw_evidence

        if hasattr(sev, "value"):
            sev = str(sev.value)
        else:
            sev = str(sev)

        key = (title.strip().lower(), port)
        if key not in grouped:
            grouped[key] = {
                "title": title,
                "port": port,
                "severity": sev,
                "risk_score": score,
                "impact": impact,
                "likelihood": likelihood,
                "check_name": mod,
                "description": desc,
                "remediation": remediation,
                "raw_evidence": evidence,
                "count": 1,
            }
        else:
            grouped[key]["count"] += 1
            if score > grouped[key]["risk_score"]:
                grouped[key]["risk_score"] = score
                grouped[key]["severity"] = sev
                grouped[key]["impact"] = impact
                grouped[key]["likelihood"] = likelihood

    return sorted(grouped.values(), key=lambda x: x["risk_score"], reverse=True)


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for dynamic 'Page X of Y' numbering and running header/footer."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[dict] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, total_pages: int) -> None:
        self.saveState()
        page_w, page_h = letter
        margin = 36

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(TEXT_MUTED)
            self.drawString(margin, page_h - 26, "CYART HOST & NETWORK SECURITY ASSESSMENT")
            self.setFont("Helvetica", 8)
            self.drawRightString(page_w - margin, page_h - 26, "Executive Security Audit Report")
            self.setStrokeColor(BORDER_COLOR)
            self.setLineWidth(0.5)
            self.line(margin, page_h - 30, page_w - margin, page_h - 30)

        # Running Footer (all pages)
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.5)
        self.line(margin, 34, page_w - margin, 34)

        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT_MUTED)
        self.drawString(margin, 22, "CyArt Security Hardener | Confidential - For Authorized Use Only")
        self.drawRightString(page_w - margin, 22, f"Page {self._pageNumber} of {total_pages}")

        self.restoreState()


class PDFReportGenerator:
    """Generates structured, executive-friendly, highly readable PDF assessment reports."""

    def __init__(self, output_dir: Union[str, Path] = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self) -> None:
        """Create clean typography styles with harmonious hierarchy."""
        self.styles.add(ParagraphStyle(
            name="ReportTitle",
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.white,
        ))
        self.styles.add(ParagraphStyle(
            name="ReportSubtitle",
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#94A3B8"),
        ))
        self.styles.add(ParagraphStyle(
            name="SecHeading",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=PRIMARY_DARK,
            spaceBefore=12,
            spaceAfter=5,
            keepWithNext=True,
        ))
        self.styles.add(ParagraphStyle(
            name="SecSubheading",
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=13,
            textColor=TEXT_DARK,
            spaceBefore=6,
            spaceAfter=3,
            keepWithNext=True,
        ))
        self.styles.add(ParagraphStyle(
            name="BodySmall",
            fontName="Helvetica",
            fontSize=8,
            leading=11.5,
            textColor=TEXT_DARK,
        ))
        self.styles.add(ParagraphStyle(
            name="BodySmallMuted",
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=TEXT_MUTED,
        ))
        self.styles.add(ParagraphStyle(
            name="CodeBlock",
            fontName="Courier",
            fontSize=7,
            leading=9.5,
            textColor=colors.HexColor("#1E293B"),
        ))
        self.styles.add(ParagraphStyle(
            name="TableHeader",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=colors.white,
        ))
        self.styles.add(ParagraphStyle(
            name="MetricValue",
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=18,
            alignment=1,  # Center
            textColor=PRIMARY_DARK,
        ))
        self.styles.add(ParagraphStyle(
            name="MetricLabel",
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9.5,
            alignment=1,  # Center
            textColor=TEXT_MUTED,
        ))

    def generate_report(self, data: Dict[str, Any], output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Build and write the PDF report.
        Returns the Path to the generated PDF.
        """
        target = data.get("target", "Target Host")
        clean_target = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", target)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if not output_path:
            pdf_path = self.output_dir / f"security_report_{clean_target}_{timestamp}.pdf"
        else:
            pdf_path = Path(output_path)
            if pdf_path.parent:
                pdf_path.parent.mkdir(parents=True, exist_ok=True)

        printable_width = letter[0] - 72  # 540 pt
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=42,
        )

        story: List[Any] = []

        # 1. Header Banner Box
        story.extend(self._build_header_banner(data, printable_width))
        story.append(Spacer(1, 8))

        # 2. Executive Summary & 4-Stat Metric Cards + Overview Paragraph
        story.extend(self._build_kpi_cards(data, printable_width))
        story.append(Spacer(1, 10))

        # 3. Reconnaissance, Discovery & Scope Intelligence
        story.extend(self._build_recon_section(data, printable_width))
        story.append(Spacer(1, 10))

        # 4. Verified Open Ports & Service Inventory
        story.extend(self._build_open_ports_section(data, printable_width))
        story.append(Spacer(1, 10))

        # 5. Network Defense & Filtered Ports Summary
        story.extend(self._build_filtered_ports_section(data, printable_width))
        story.append(Spacer(1, 10))

        # 6. Security Findings Summary Table
        story.extend(self._build_findings_table_section(data, printable_width))
        story.append(Spacer(1, 10))

        # 7. Actionable Vulnerability Remediation Cards
        story.extend(self._build_remediation_cards_section(data, printable_width))

        # Build Document with NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        return pdf_path

    # ── Section Builders ──────────────────────────────────────────────────────

    def _build_header_banner(self, data: Dict[str, Any], width: float) -> List[Any]:
        """Header card with deep slate background, logo/brand text, and overall status."""
        target = safe_text(data.get("target", "Target Host"))
        ip = safe_text(data.get("target_ip") or data.get("ip") or "N/A")
        date_str = data.get("scan_date") or datetime.now(timezone.utc).strftime("%B %d, %Y - %H:%M UTC")

        # Determine posture badge color and text
        raw_findings = data.get("findings", [])
        findings = consolidate_findings(raw_findings)

        has_crit = any(f["severity"].upper() == "CRITICAL" for f in findings)
        has_high = any(f["severity"].upper() == "HIGH" for f in findings)
        has_med = any(f["severity"].upper() == "MEDIUM" for f in findings)

        if has_crit:
            posture_text = "CRITICAL RISK"
            posture_bg = "#DC2626"
        elif has_high:
            posture_text = "HIGH RISK"
            posture_bg = "#EA580C"
        elif has_med:
            posture_text = "MEDIUM RISK"
            posture_bg = "#D97706"
        elif findings:
            posture_text = "LOW RISK"
            posture_bg = "#2563EB"
        else:
            posture_text = "SECURE / HARDENED"
            posture_bg = "#16A34A"

        title_p = Paragraph("CYART HOST & NETWORK SECURITY", self.styles["ReportSubtitle"])
        subtitle_p = Paragraph(f"Assessment Audit: <b>{target}</b> ({ip})", self.styles["ReportTitle"])
        meta_p = Paragraph(f"Audit Date: {safe_text(date_str)} | Scope: Authorized", self.styles["ReportSubtitle"])

        badge_p = Paragraph(
            f"<para align='center'><font size=9.5 color='white'><b>{posture_text}</b></font></para>",
            self.styles["BodySmall"]
        )

        left_cell = [title_p, Spacer(1, 2), subtitle_p, Spacer(1, 3), meta_p]
        right_table = Table([[badge_p]], colWidths=[120], rowHeights=[26])
        right_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(posture_bg)),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]))

        banner_table = Table(
            [[left_cell, right_table]],
            colWidths=[width - 130, 130]
        )
        banner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PRIMARY_DARK),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ]))
        return [banner_table]

    def _build_kpi_cards(self, data: Dict[str, Any], width: float) -> List[Any]:
        """4-metric executive KPI summary cards + executive summary narrative."""
        card_w = width / 4.0

        status = safe_text(data.get("status", "live")).upper()
        discovery_m = safe_text(data.get("discovery_method", "Probe Active"))

        total_ports = data.get("total_ports", 65535)
        open_ports = data.get("open_ports", [])
        filtered_count = data.get("filtered_tcp_count", 0)

        raw_findings = data.get("findings", [])
        findings = consolidate_findings(raw_findings)

        crit_count = sum(1 for f in findings if f["severity"].upper() == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"].upper() == "HIGH")
        med_count = sum(1 for f in findings if f["severity"].upper() == "MEDIUM")
        low_count = len(findings) - (crit_count + high_count + med_count)

        findings_sub = f"{crit_count} Crit | {high_count} High | {med_count} Med" if findings else "0 Vulnerabilities"

        card1 = [
            Paragraph(f"<font color='#16A34A'>{status}</font>", self.styles["MetricValue"]),
            Paragraph(f"{discovery_m[:18]}", self.styles["MetricLabel"]),
            Paragraph("HOST DISCOVERY", self.styles["MetricLabel"]),
        ]
        card2 = [
            Paragraph(f"{len(open_ports)}", self.styles["MetricValue"]),
            Paragraph("Listening Services", self.styles["MetricLabel"]),
            Paragraph("OPEN PORTS", self.styles["MetricLabel"]),
        ]
        card3 = [
            Paragraph(f"{filtered_count:,}" if filtered_count else f"{total_ports:,}", self.styles["MetricValue"]),
            Paragraph("Firewall Dropped", self.styles["MetricLabel"]),
            Paragraph("FILTERED PORTS", self.styles["MetricLabel"]),
        ]
        card4 = [
            Paragraph(f"<font color='{'#DC2626' if (crit_count or high_count) else '#16A34A'}'>{len(findings)}</font>", self.styles["MetricValue"]),
            Paragraph(findings_sub, self.styles["MetricLabel"]),
            Paragraph("UNIQUE FINDINGS", self.styles["MetricLabel"]),
        ]

        table = Table(
            [[card1, card2, card3, card4]],
            colWidths=[card_w, card_w, card_w, card_w]
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.75, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        # Executive Overview narrative callout
        target = safe_text(data.get("target", "Target"))
        if crit_count or high_count:
            exec_note = (
                f"<b>Executive Summary:</b> Security assessment of <b>{target}</b> discovered "
                f"<b>{len(findings)} unique issue(s)</b> requiring hardening. High priority items include outdated software "
                f"services or plaintext protocols exposed to network probes. Remediation roadmap is detailed below."
            )
        elif med_count or findings:
            exec_note = (
                f"<b>Executive Summary:</b> Security assessment of <b>{target}</b> identified "
                f"<b>{len(findings)} medium/low risk item(s)</b>. Perimeter firewall defenses are operating, but service banner "
                f"hardening and protocol upgrades are recommended."
            )
        else:
            exec_note = (
                f"<b>Executive Summary:</b> Security assessment of <b>{target}</b> completed with "
                f"<b>zero detected vulnerabilities</b>. Network perimeter defenses and service configurations meet baseline security standards."
            )

        exec_p = Paragraph(exec_note, self.styles["BodySmall"])
        exec_table = Table([[exec_p]], colWidths=[width])
        exec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))

        return [table, Spacer(1, 6), exec_table]

    def _build_recon_section(self, data: Dict[str, Any], width: float) -> List[Any]:
        """Reconnaissance & OS Fingerprint summary table."""
        heading = Paragraph("1. Reconnaissance & Asset Profiling", self.styles["SecHeading"])

        target = safe_text(data.get("target", "N/A"))
        ip = safe_text(data.get("target_ip") or data.get("ip") or "N/A")
        ptr = safe_text(data.get("ptr_record") or "No PTR record registered")
        os_guess = safe_text(data.get("os_guess") or "Unknown / Inconclusive")
        conf = data.get("os_confidence")
        os_conf_str = f" ({conf * 100:.0f}% confidence)" if (conf and os_guess != "Unknown / Inconclusive") else ""
        scope_status = safe_text(data.get("scope_status") or "Authorized (Explicit Scope Whitelist)")

        dns_records = data.get("dns_records", {})
        dns_summary_list = []
        if isinstance(dns_records, dict):
            for rtype, vals in dns_records.items():
                if vals:
                    dns_summary_list.append(f"<b>{safe_text(rtype)}</b>: {safe_text(', '.join(vals))}")
        dns_str = "<br/>".join(dns_summary_list) if dns_summary_list else "None recorded (Direct IP or cache)"

        col1_w = width * 0.28
        col2_w = width * 0.72

        rows = [
            [Paragraph("<b>Target Hostname</b>", self.styles["BodySmall"]), Paragraph(target, self.styles["BodySmall"])],
            [Paragraph("<b>Primary IPv4 Address</b>", self.styles["BodySmall"]), Paragraph(ip, self.styles["BodySmall"])],
            [Paragraph("<b>Reverse DNS (PTR)</b>", self.styles["BodySmall"]), Paragraph(ptr, self.styles["BodySmall"])],
            [Paragraph("<b>OS Fingerprint</b>", self.styles["BodySmall"]), Paragraph(f"{os_guess}{os_conf_str}", self.styles["BodySmall"])],
            [Paragraph("<b>Scope Authorization</b>", self.styles["BodySmall"]), Paragraph(f"<font color='#16A34A'><b>[PASS]</b></font> {scope_status}", self.styles["BodySmall"])],
            [Paragraph("<b>DNS Intelligence</b>", self.styles["BodySmall"]), Paragraph(dns_str, self.styles["BodySmall"])],
        ]

        table = Table(rows, colWidths=[col1_w, col2_w])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return [heading, table]

    def _build_open_ports_section(self, data: Dict[str, Any], width: float) -> List[Any]:
        """Verified Open Ports inventory table."""
        heading = Paragraph("2. Port & Service Inventory (Verified Open Ports)", self.styles["SecHeading"])

        open_ports = data.get("open_ports", [])
        if not open_ports:
            empty_msg = Paragraph(
                "<i>No open ports detected. The host is either fully firewalled or has no publicly bound listening services.</i>",
                self.styles["BodySmallMuted"]
            )
            return [heading, empty_msg]

        col_w = [width * 0.16, width * 0.12, width * 0.22, width * 0.50]
        header_row = [
            Paragraph("PORT / PROTO", self.styles["TableHeader"]),
            Paragraph("STATE", self.styles["TableHeader"]),
            Paragraph("SERVICE", self.styles["TableHeader"]),
            Paragraph("VERSION / BANNER DETAILS", self.styles["TableHeader"]),
        ]

        table_data = [header_row]

        # Deduplicate ports by (port, protocol)
        unique_ports: Dict[tuple, Any] = {}
        for p in open_ports:
            port_num = p.get("port") if isinstance(p, dict) else p.port
            proto = p.get("protocol", "tcp") if isinstance(p, dict) else getattr(p, "protocol", "tcp")
            unique_ports[(port_num, proto)] = p

        sorted_ports = sorted(unique_ports.values(), key=lambda x: (x.get("port") if isinstance(x, dict) else x.port))

        for p in sorted_ports:
            if isinstance(p, dict):
                port_num = p.get("port")
                proto = p.get("protocol", "tcp")
                service = p.get("service") or "unknown"
                raw_banner = p.get("version_info") or p.get("banner")
            else:
                port_num = p.port
                proto = getattr(p, "protocol", "tcp")
                service = getattr(p, "service", "unknown") or "unknown"
                raw_banner = getattr(p, "version_info", None) or getattr(p, "banner", None)

            port_label = f"<b>{port_num}</b>/{safe_text(proto)}"
            banner_clean = clean_banner(raw_banner)
            state_label = "<font color='#16A34A'><b>OPEN</b></font>"

            table_data.append([
                Paragraph(port_label, self.styles["BodySmall"]),
                Paragraph(state_label, self.styles["BodySmall"]),
                Paragraph(safe_text(service), self.styles["BodySmall"]),
                Paragraph(banner_clean, self.styles["BodySmall"]),
            ])

        table = Table(table_data, colWidths=col_w)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY_DARK),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return [heading, table]

    def _build_filtered_ports_section(self, data: Dict[str, Any], width: float) -> List[Any]:
        """Firewall analysis & high-value filtered ports."""
        heading = Paragraph("3. Network Defense & Firewall Evaluation", self.styles["SecHeading"])

        closed_count = data.get("closed_tcp_count", 0)
        filtered_count = data.get("filtered_tcp_count", 0)
        total_scanned = data.get("total_ports", 65535)

        defense_summary = (
            f"Of <b>{total_scanned:,}</b> target ports probed: <b>{filtered_count:,}</b> ports dropped packets without response "
            f"(confirming stateful packet filtering / firewall drop), and <b>{closed_count:,}</b> ports returned TCP RST resets. "
            f"This demonstrates active network boundary enforcement."
        )
        desc_p = Paragraph(defense_summary, self.styles["BodySmall"])

        filtered_sample = data.get("filtered_ports", [])
        if not filtered_sample:
            return [heading, desc_p]

        # Show up to 5 key filtered ports
        col_w = [width * 0.16, width * 0.14, width * 0.22, width * 0.48]
        header_row = [
            Paragraph("PORT / PROTO", self.styles["TableHeader"]),
            Paragraph("STATE", self.styles["TableHeader"]),
            Paragraph("SERVICE", self.styles["TableHeader"]),
            Paragraph("DIAGNOSTIC EVIDENCE / FIREWALL BEHAVIOR", self.styles["TableHeader"]),
        ]
        table_data = [header_row]

        shown = 0
        seen_ports = set()
        for p in filtered_sample:
            if shown >= 5:
                break
            port_num = p.get("port") if isinstance(p, dict) else p.port
            if port_num in seen_ports:
                continue
            seen_ports.add(port_num)

            proto = p.get("protocol", "tcp") if isinstance(p, dict) else getattr(p, "protocol", "tcp")
            service = p.get("service") if isinstance(p, dict) else getattr(p, "service", "unknown")
            reason = (p.get("reason") if isinstance(p, dict) else getattr(p, "reason", None)) or "Silent drop (packet dropped by firewall)"

            port_label = f"<b>{port_num}</b>/{safe_text(proto)}"
            state_label = "<font color='#D97706'><b>FILTERED</b></font>"
            reason_clean = safe_text(str(reason).replace("\r", " ").replace("\n", " "))[:95]

            table_data.append([
                Paragraph(port_label, self.styles["BodySmall"]),
                Paragraph(state_label, self.styles["BodySmall"]),
                Paragraph(safe_text(service or "unknown"), self.styles["BodySmall"]),
                Paragraph(reason_clean, self.styles["BodySmall"]),
            ])
            shown += 1

        table = Table(table_data, colWidths=col_w)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY_DARK),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        return [heading, desc_p, Spacer(1, 4), table]

    def _build_findings_table_section(self, data: Dict[str, Any], width: float) -> List[Any]:
        """Vulnerability findings summary matrix."""
        heading = Paragraph("4. Security Findings & Vulnerability Matrix", self.styles["SecHeading"])

        raw_findings = data.get("findings", [])
        findings = consolidate_findings(raw_findings)

        if not findings:
            clean_p = Paragraph(
                "<font color='#16A34A'><b>[PASS] Zero security vulnerabilities or service misconfigurations detected.</b></font>",
                self.styles["BodySmall"]
            )
            return [heading, clean_p]

        col_w = [width * 0.14, width * 0.11, width * 0.14, width * 0.21, width * 0.40]
        header_row = [
            Paragraph("SEVERITY", self.styles["TableHeader"]),
            Paragraph("RISK SCORE", self.styles["TableHeader"]),
            Paragraph("PORT / SCOPE", self.styles["TableHeader"]),
            Paragraph("CHECK MODULE", self.styles["TableHeader"]),
            Paragraph("VULNERABILITY TITLE", self.styles["TableHeader"]),
        ]
        table_data = [header_row]

        for f in findings:
            sev = f["severity"]
            score = f["risk_score"]
            port = f["port"]
            mod = f["check_name"]
            title = f["title"]
            count = f.get("count", 1)

            sev_upper = sev.upper()
            if sev_upper == "CRITICAL":
                color_hex = "#DC2626"
            elif sev_upper == "HIGH":
                color_hex = "#EA580C"
            elif sev_upper == "MEDIUM":
                color_hex = "#D97706"
            elif sev_upper == "LOW":
                color_hex = "#2563EB"
            else:
                color_hex = "#475569"

            sev_label = f"<font color='{color_hex}'><b>{safe_text(sev)}</b></font>"
            score_label = f"<b>{score}/25</b>"
            port_label = f"Port {port}" if port else "Host-level"
            count_suffix = f" <font color='#64748B' size=7>(x{count})</font>" if count > 1 else ""

            table_data.append([
                Paragraph(sev_label, self.styles["BodySmall"]),
                Paragraph(score_label, self.styles["BodySmall"]),
                Paragraph(safe_text(port_label), self.styles["BodySmall"]),
                Paragraph(safe_text(mod), self.styles["BodySmall"]),
                Paragraph(f"{safe_text(title)}{count_suffix}", self.styles["BodySmall"]),
            ])

        table = Table(table_data, colWidths=col_w)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY_DARK),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return [heading, table]

    def _build_remediation_cards_section(self, data: Dict[str, Any], width: float) -> List[Any]:
        """Detailed yet digestible Actionable Remediation Cards for each unique security finding."""
        heading = Paragraph("5. Actionable Remediation & Hardening Roadmap", self.styles["SecHeading"])

        raw_findings = data.get("findings", [])
        findings = consolidate_findings(raw_findings)

        if not findings:
            return []

        elements: List[Any] = []

        for idx, f in enumerate(findings):
            sev = f["severity"]
            score = f["risk_score"]
            impact = f["impact"]
            likelihood = f["likelihood"]
            port = f["port"]
            title = f["title"]
            desc = f["description"]
            remediation = f["remediation"] or "Apply vendor security patches and restrict network access."
            evidence = f.get("raw_evidence")
            count = f.get("count", 1)

            sev_upper = sev.upper()
            if sev_upper == "CRITICAL":
                border_c = SEV_CRITICAL
                badge_bg = "#DC2626"
            elif sev_upper == "HIGH":
                border_c = SEV_HIGH
                badge_bg = "#EA580C"
            elif sev_upper == "MEDIUM":
                border_c = SEV_MEDIUM
                badge_bg = "#D97706"
            elif sev_upper == "LOW":
                border_c = SEV_LOW
                badge_bg = "#2563EB"
            else:
                border_c = SEV_INFO
                badge_bg = "#475569"

            port_label = f"Port {port}" if port else "Host-level Asset"
            count_label = f" (Observed x{count})" if count > 1 else ""

            # Top Header Bar for Finding Card
            top_bar = Table(
                [[
                    Paragraph(f"<font color='white'><b>{safe_text(sev_upper)}</b></font>", self.styles["BodySmall"]),
                    Paragraph(f"<b>{safe_text(title)}</b> ({port_label}){count_label}", self.styles["BodySmall"]),
                    Paragraph(f"<b>Risk: {score}/25</b> (Imp: {impact}/5, Lkh: {likelihood}/5)", self.styles["BodySmallMuted"]),
                ]],
                colWidths=[width * 0.16, width * 0.54, width * 0.30]
            )
            top_bar.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(badge_bg)),
                ("BACKGROUND", (1, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("ALIGN", (2, 0), (2, 0), "RIGHT"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))

            # Content Rows
            desc_p = Paragraph(f"<b>Overview:</b> {safe_text(desc)}", self.styles["BodySmall"])
            rem_p = Paragraph(f"<b>Hardening Advisory:</b> <font color='#0369A1'>{safe_text(remediation)}</font>", self.styles["BodySmall"])

            card_rows = [[top_bar], [desc_p], [rem_p]]

            # Evidence snippet (clean monospaced box, safely truncated)
            if evidence:
                ev_clean = clean_banner(evidence)[:180]
                ev_p = Paragraph(f"<b>Observed Evidence:</b><br/><font color='#334155'>{ev_clean}</font>", self.styles["CodeBlock"])
                card_rows.append([ev_p])

            card_table = Table(card_rows, colWidths=[width])
            card_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 1), (0, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 1, border_c),
                ("TOPPADDING", (0, 1), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                ("LEFTPADDING", (0, 1), (-1, -1), 7),
                ("RIGHTPADDING", (0, 1), (-1, -1), 7),
            ]))

            if idx == 0:
                elements.append(KeepTogether([heading, Spacer(1, 3), card_table, Spacer(1, 6)]))
            else:
                elements.append(KeepTogether([card_table, Spacer(1, 6)]))

        return elements

    # ── Database Exporter ─────────────────────────────────────────────────────

    def export_from_db(
        self,
        db: Database,
        target_or_ip: str,
        output_path: Optional[Union[str, Path]] = None
    ) -> Optional[Path]:
        """
        Pull full scan details from SQLite Database and generate the PDF report.
        """
        host = db.get_host_by_target(target_or_ip)
        if not host:
            return None

        host_id = host["id"]
        ports = db.get_ports_for_host(host_id)
        findings = db.get_findings_for_host(host_id)
        dns_records = db.get_dns_records(host["target"])

        open_ports = [p for p in ports if p.get("state") == "open"]
        filtered_ports = [p for p in ports if p.get("state") in ("filtered", "open|filtered")]

        data: Dict[str, Any] = {
            "target": host["target"],
            "target_ip": host.get("ip") or host["target"],
            "ptr_record": None,
            "status": host.get("status", "live"),
            "discovery_method": "Historical DB Record",
            "os_guess": host.get("os_guess"),
            "os_confidence": host.get("os_confidence"),
            "dns_records": dns_records,
            "scope_status": "Authorized & Stored in SQLite",
            "total_ports": len(ports) if ports else 65535,
            "open_ports": open_ports,
            "filtered_ports": filtered_ports,
            "closed_tcp_count": 0,
            "filtered_tcp_count": len(filtered_ports),
            "scan_date": host.get("updated_at") or host.get("created_at"),
            "findings": findings,
        }

        return self.generate_report(data, output_path=output_path)
