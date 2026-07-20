"""
CyberSentinel - PDF Report Generator
======================================
Generates professional incident response PDF reports.
Uses ReportLab (no external services needed).
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime
import io

from copilot.security_copilot import CopilotResponse


# ── Brand Colors ──
DARK_BG = HexColor("#0D1117")
ACCENT = HexColor("#00D4FF")
DANGER = HexColor("#FF4444")
WARNING = HexColor("#FF8C00")
SUCCESS = HexColor("#00C851")
TEXT = HexColor("#E6EDF3")
CARD_BG = HexColor("#161B22")
BORDER = HexColor("#30363D")

SEVERITY_COLORS = {
    "critical": HexColor("#FF0000"),
    "high": HexColor("#FF4444"),
    "medium": HexColor("#FF8C00"),
    "low": HexColor("#FFD700"),
    "info": HexColor("#00D4FF"),
}

TIMEFRAME_COLORS = {
    "immediate": HexColor("#FF4444"),
    "short_term": HexColor("#FF8C00"),
    "long_term": HexColor("#00C851"),
}


def generate_pdf_report(response: CopilotResponse) -> bytes:
    """Generate a PDF incident response report. Returns bytes."""
    
    buffer = io.BytesIO()
    
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15*mm,
        leftMargin=15*mm,
        topMargin=15*mm,
        bottomMargin=15*mm
    )
    
    styles = _build_styles()
    story = []
    
    # Header
    story += _build_header(response, styles)
    story.append(Spacer(1, 8*mm))
    
    # Executive Summary
    story += _build_summary_section(response, styles)
    story.append(Spacer(1, 6*mm))
    
    # Threat Overview Table
    if response.suspicious_ips or response.threat_types_detected:
        story += _build_threat_table(response, styles)
        story.append(Spacer(1, 6*mm))
    
    # Incident Response Playbook
    if response.playbook:
        story += _build_playbook_section(response, styles)
        story.append(Spacer(1, 6*mm))
    
    # Recommendations
    if response.recommendations:
        story += _build_recommendations_section(response, styles)
        story.append(Spacer(1, 6*mm))
    
    # Raw Log Analysis
    if response.raw_log_analysis:
        story += _build_raw_analysis_section(response, styles)
    
    # Footer
    story.append(Spacer(1, 8*mm))
    story += _build_footer(response, styles)
    
    doc.build(story)
    return buffer.getvalue()


def _build_styles():
    styles = getSampleStyleSheet()
    
    custom = {
        "title": ParagraphStyle(
            "title", fontSize=22, textColor=ACCENT,
            fontName="Helvetica-Bold", spaceAfter=2*mm, leading=26
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontSize=11, textColor=HexColor("#8B949E"),
            fontName="Helvetica", spaceAfter=1*mm
        ),
        "section_header": ParagraphStyle(
            "section_header", fontSize=13, textColor=ACCENT,
            fontName="Helvetica-Bold", spaceBefore=3*mm, spaceAfter=2*mm
        ),
        "body": ParagraphStyle(
            "body", fontSize=10, textColor=HexColor("#C9D1D9"),
            fontName="Helvetica", leading=15, spaceAfter=2*mm
        ),
        "bold_body": ParagraphStyle(
            "bold_body", fontSize=10, textColor=HexColor("#E6EDF3"),
            fontName="Helvetica-Bold", leading=15
        ),
        "small": ParagraphStyle(
            "small", fontSize=8, textColor=HexColor("#8B949E"),
            fontName="Helvetica", leading=12
        ),
        "step_action": ParagraphStyle(
            "step_action", fontSize=10, textColor=white,
            fontName="Helvetica-Bold", leading=14
        ),
        "step_reason": ParagraphStyle(
            "step_reason", fontSize=9, textColor=HexColor("#C9D1D9"),
            fontName="Helvetica", leading=13
        ),
        "monospace": ParagraphStyle(
            "monospace", fontSize=8, textColor=HexColor("#7EE787"),
            fontName="Courier", leading=12, spaceAfter=1*mm
        ),
    }
    
    return custom


def _build_header(response: CopilotResponse, styles) -> list:
    elements = []
    
    severity_color = SEVERITY_COLORS.get(response.severity_overall, WARNING)
    severity_label = response.severity_overall.upper()
    
    # Title row with severity badge
    title_data = [[
        Paragraph("CyberSentinel", styles["title"]),
        Paragraph(
            f'<font color="#{severity_color.hexval()[2:].upper()}">'
            f'● {severity_label}</font>',
            ParagraphStyle("badge", fontSize=14, fontName="Helvetica-Bold",
                          textColor=severity_color, alignment=TA_RIGHT)
        )
    ]]
    
    title_table = Table(title_data, colWidths=["70%", "30%"])
    title_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    elements.append(title_table)
    
    elements.append(Paragraph("Incident Response Report", styles["subtitle"]))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"Mode: {response.mode.replace('_', ' ').title()}",
        styles["small"]
    ))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=ACCENT))
    
    return elements


def _build_summary_section(response: CopilotResponse, styles) -> list:
    elements = []
    
    elements.append(Paragraph("Executive Summary", styles["section_header"]))
    elements.append(Paragraph(response.plain_english_summary, styles["body"]))
    
    # Stats row
    stats_data = [[
        _stat_cell("Severity", response.severity_overall.upper(),
                   SEVERITY_COLORS.get(response.severity_overall, WARNING)),
        _stat_cell("Threats Found", str(len(response.threat_types_detected)), ACCENT),
        _stat_cell("Suspicious IPs", str(len(response.suspicious_ips)), WARNING),
        _stat_cell("Response Steps", str(len(response.playbook)), SUCCESS),
    ]]
    
    stats_table = Table(stats_data, colWidths=["25%", "25%", "25%", "25%"])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
        ("ROUNDEDCORNERS", [4], []),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("LINEAFTER", (0, 0), (2, 0), 0.5, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4*mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4*mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 3*mm),
    ]))
    elements.append(stats_table)
    
    return elements


def _stat_cell(label: str, value: str, color) -> Paragraph:
    return Paragraph(
        f'<font size="8" color="#8B949E">{label}</font><br/>'
        f'<font size="16" color="#{color.hexval()[2:].upper()}">'
        f'<b>{value}</b></font>',
        ParagraphStyle("stat", fontName="Helvetica", leading=20)
    )


def _build_threat_table(response: CopilotResponse, styles) -> list:
    elements = []
    elements.append(Paragraph("Threat Overview", styles["section_header"]))
    
    # Threat types
    if response.threat_types_detected:
        threat_list = " | ".join(
            t.replace("_", " ").title() for t in response.threat_types_detected
        )
        elements.append(Paragraph(f"Detected: {threat_list}", styles["bold_body"]))
        elements.append(Spacer(1, 2*mm))
    
    # Suspicious IPs table
    if response.suspicious_ips:
        elements.append(Paragraph("Suspicious IP Addresses:", styles["bold_body"]))
        
        ip_data = [["IP Address", "Status"]]
        for ip in response.suspicious_ips[:10]:  # Cap at 10
            ip_data.append([ip, "⚠ Flagged"])
        
        ip_table = Table(ip_data, colWidths=["70%", "30%"])
        ip_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), black),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 1), (-1, -1), CARD_BG),
            ("TEXTCOLOR", (0, 1), (-1, -1), HexColor("#C9D1D9")),
            ("TEXTCOLOR", (1, 1), (1, -1), WARNING),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [CARD_BG, HexColor("#1C2128")]),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 2*mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2*mm),
            ("LEFTPADDING", (0, 0), (-1, -1), 3*mm),
        ]))
        elements.append(ip_table)
    
    return elements


def _build_playbook_section(response: CopilotResponse, styles) -> list:
    elements = []
    elements.append(Paragraph("Incident Response Playbook", styles["section_header"]))
    
    # Group by timeframe
    timeframes = {
        "immediate": ("🚨 Immediate Actions", TIMEFRAME_COLORS["immediate"]),
        "short_term": ("⚡ Short-Term Actions (24-48 hours)", TIMEFRAME_COLORS["short_term"]),
        "long_term": ("🛡 Long-Term Actions (1 week+)", TIMEFRAME_COLORS["long_term"]),
    }
    
    steps_by_timeframe = {"immediate": [], "short_term": [], "long_term": []}
    for step in response.playbook:
        tf = step.timeframe if step.timeframe in steps_by_timeframe else "short_term"
        steps_by_timeframe[tf].append(step)
    
    for timeframe_key, (label, color) in timeframes.items():
        steps = steps_by_timeframe[timeframe_key]
        if not steps:
            continue
        
        elements.append(Paragraph(
            f'<font color="#{color.hexval()[2:].upper()}">{label}</font>',
            ParagraphStyle("tf_label", fontSize=11, fontName="Helvetica-Bold",
                          spaceBefore=2*mm, spaceAfter=1*mm)
        ))
        
        step_rows = []
        for step in steps:
            step_rows.append([
                Paragraph(f"{step.priority}", ParagraphStyle(
                    "num", fontSize=14, fontName="Helvetica-Bold",
                    textColor=color, alignment=TA_CENTER
                )),
                [
                    Paragraph(step.action, styles["step_action"]),
                    Paragraph(step.reason, styles["step_reason"])
                ]
            ])
        
        step_table = Table(step_rows, colWidths=["8%", "92%"])
        step_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 3*mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3*mm),
            ("LEFTPADDING", (0, 0), (-1, -1), 3*mm),
            ("LINEBELOW", (0, 0), (-1, -2), 0.3, BORDER),
            ("BOX", (0, 0), (-1, -1), 0.5, color),
        ]))
        elements.append(step_table)
        elements.append(Spacer(1, 2*mm))
    
    return elements


def _build_recommendations_section(response: CopilotResponse, styles) -> list:
    elements = []
    elements.append(Paragraph("Long-Term Security Recommendations", styles["section_header"]))
    
    for i, rec in enumerate(response.recommendations, 1):
        elements.append(Paragraph(f"{i}. {rec}", styles["body"]))
    
    return elements


def _build_raw_analysis_section(response: CopilotResponse, styles) -> list:
    elements = []
    elements.append(Paragraph("Raw Log Analysis", styles["section_header"]))
    
    # Wrap in monospace style
    for line in response.raw_log_analysis.split('\n')[:30]:  # Cap lines
        if line.strip():
            elements.append(Paragraph(line, styles["monospace"]))
    
    return elements


def _build_footer(response: CopilotResponse, styles) -> list:
    elements = []
    elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    
    sources = ", ".join(response.sources_used) if response.sources_used else "CyberSentinel KB"
    elements.append(Paragraph(
        f"Sources: {sources} | "
        f"CyberSentinel Security Platform | "
        f"This report is AI-generated and should be reviewed by a security professional.",
        styles["small"]
    ))
    
    return elements


if __name__ == "__main__":
    # Test with dummy data
    from security_copilot import CopilotResponse, PlaybookStep
    
    test_response = CopilotResponse(
        mode="log_analysis",
        plain_english_summary="Two suspicious IP addresses were detected targeting your server. One was attempting to brute-force your SSH login (10 failed attempts), and another was scanning your server for open ports and discovered several sensitive services.",
        severity_overall="high",
        threat_types_detected=["brute_force", "port_scan"],
        suspicious_ips=["185.220.101.45", "45.33.32.156"],
        playbook=[
            PlaybookStep(1, "immediate", "Block IP 185.220.101.45 in your firewall immediately", "This IP has attempted to login via SSH 10 times and must be stopped."),
            PlaybookStep(2, "immediate", "Block IP 45.33.32.156 in your firewall", "This IP conducted a port scan and now knows which services are running."),
            PlaybookStep(3, "short_term", "Enable multi-factor authentication on SSH", "Password-only SSH is vulnerable to brute force attacks."),
            PlaybookStep(4, "long_term", "Disable password authentication for SSH, use key-based auth only", "Eliminates brute force as an attack vector entirely."),
        ],
        recommendations=[
            "Enable fail2ban to automatically block IPs after failed login attempts",
            "Move SSH to a non-standard port to reduce automated scanning",
            "Close MongoDB port 27017 - it should never be internet-facing",
            "Close Redis port 6379 - it has no authentication by default"
        ],
        sources_used=["NIST SP 800-61 Rev 2", "CyberSentinel Pattern Library"],
        raw_log_analysis="LOG ANALYSIS SUMMARY\nLog Type: UFW\n2 events detected"
    )
    
    pdf = generate_pdf_report(test_response)
    with open("/mnt/user-data/outputs/test_report.pdf", "wb") as f:
        f.write(pdf)
    print(f"Test PDF generated: {len(pdf)} bytes")
