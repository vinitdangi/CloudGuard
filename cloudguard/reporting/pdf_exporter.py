"""Create an in-memory PDF report from CloudGuard findings and scan metadata."""

import html
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

PROJECT_NAME = (
    "CloudGuard - AWS Cloud Security Misconfiguration Detection & "
    "Risk Assessment Platform"
)
NAVY = colors.HexColor("#17324D")
TEAL = colors.HexColor("#0E9F91")
INK = colors.HexColor("#263746")
MUTED = colors.HexColor("#607386")
PALE = colors.HexColor("#F1F5F8")
GRID = colors.HexColor("#D9E2EA")
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#8E2635"),
    "HIGH": colors.HexColor("#C0392B"),
    "MEDIUM": colors.HexColor("#B56B00"),
    "LOW": colors.HexColor("#26734D"),
    "PASS": TEAL,
}
SENSITIVE_KEY_PARTS = (
    "secret",
    "password",
    "credential",
    "session",
    "token",
    "authorization",
    "accesskey",
)


def _is_sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def _sanitize(value: Any, sensitive_values: tuple[str, ...] = ()) -> Any:
    """Remove credential-shaped fields and supplied secret values recursively."""
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if _is_sensitive_key(key) else _sanitize(item, sensitive_values)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item, sensitive_values) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    for sensitive_value in sensitive_values:
        if sensitive_value:
            text = text.replace(sensitive_value, "[REDACTED]")
    return text


def _finding_data(finding: Any, sensitive_values: tuple[str, ...]) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        data = dict(finding.to_dict())
        for attribute in (
            "cis_control",
            "cis_title",
            "cis_benchmark",
            "cis_version",
        ):
            value = getattr(finding, attribute, None)
            if value:
                data[attribute] = value
        if getattr(finding, "compliance", None):
            data["compliance"] = finding.compliance
    elif isinstance(finding, Mapping):
        data = dict(finding)
    else:
        data = {"check": str(finding)}
    return _sanitize(data, sensitive_values)


def _text(value: Any) -> str:
    if value is None or value == "":
        return "Not provided"
    if isinstance(value, (Mapping, list, tuple)):
        value = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
    return html.escape(str(value), quote=True).replace("\n", "<br/>")


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_text(value), style)


def _severity_paragraph(severity: str, style: ParagraphStyle) -> Paragraph:
    color = SEVERITY_COLORS[severity].hexval()
    return Paragraph(f'<font color="{color}"><b>{severity}</b></font>', style)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "CloudGuardCoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=25, leading=30, textColor=NAVY, alignment=TA_CENTER, spaceAfter=10,
        ),
        "cover_subtitle": ParagraphStyle(
            "CloudGuardCoverSubtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=15, leading=20, textColor=TEAL, alignment=TA_CENTER, spaceAfter=12,
        ),
        "project": ParagraphStyle(
            "CloudGuardProject", parent=base["Normal"], fontName="Helvetica",
            fontSize=10, leading=15, textColor=MUTED, alignment=TA_CENTER,
        ),
        "section": ParagraphStyle(
            "CloudGuardSection", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=16, leading=20, textColor=NAVY, spaceBefore=8, spaceAfter=9,
            keepWithNext=True,
        ),
        "subsection": ParagraphStyle(
            "CloudGuardSubsection", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=11, leading=14, textColor=NAVY, spaceBefore=7, spaceAfter=5,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "CloudGuardBody", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8.5, leading=12, textColor=INK, spaceAfter=4, wordWrap="CJK",
        ),
        "detail_severity": ParagraphStyle(
            "CloudGuardDetailSeverity", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8.5, leading=12, textColor=INK, spaceAfter=4, keepWithNext=True,
        ),
        "small": ParagraphStyle(
            "CloudGuardSmall", parent=base["BodyText"], fontName="Helvetica",
            fontSize=7.2, leading=9.5, textColor=INK, wordWrap="CJK",
        ),
        "table_header": ParagraphStyle(
            "CloudGuardTableHeader", parent=base["BodyText"], fontName="Helvetica-Bold",
            fontSize=7.2, leading=9, textColor=colors.white,
        ),
        "label": ParagraphStyle(
            "CloudGuardLabel", parent=base["BodyText"], fontName="Helvetica-Bold",
            fontSize=7.5, leading=10, textColor=MUTED,
        ),
        "metric": ParagraphStyle(
            "CloudGuardMetric", parent=base["BodyText"], fontName="Helvetica-Bold",
            fontSize=17, leading=20, textColor=NAVY, alignment=TA_CENTER,
        ),
        "metric_label": ParagraphStyle(
            "CloudGuardMetricLabel", parent=base["BodyText"], fontName="Helvetica",
            fontSize=7.2, leading=9, textColor=MUTED, alignment=TA_CENTER,
        ),
        "center": ParagraphStyle(
            "CloudGuardCenter", parent=base["BodyText"], fontName="Helvetica-Bold",
            fontSize=8, leading=10, textColor=INK, alignment=TA_CENTER,
        ),
    }


def _page_chrome(canvas, document) -> None:
    canvas.saveState()
    width, height = letter
    canvas.setStrokeColor(GRID)
    canvas.setLineWidth(0.6)
    canvas.line(document.leftMargin, height - 34, width - document.rightMargin, height - 34)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(NAVY)
    canvas.drawString(document.leftMargin, height - 27, "CLOUDGUARD  /  SECURITY ASSESSMENT")
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.line(document.leftMargin, 34, width - document.rightMargin, 34)
    canvas.drawString(document.leftMargin, 22, "Read-only assessment - handle this report as security-sensitive")
    canvas.drawRightString(width - document.rightMargin, 22, f"Page {document.page}")
    canvas.restoreState()


def _metadata_value(metadata: Mapping[str, Any], *keys: str, default: Any = "Not provided") -> Any:
    for key in keys:
        value = metadata.get(key)
        if value is not None and value != "":
            return value
    return default


def _severity(finding: Mapping[str, Any]) -> str:
    if finding.get("passed"):
        return "PASS"
    value = str(finding.get("severity") or "HIGH").upper()
    return value if value in SEVERITY_COLORS else "HIGH"


def generate_pdf_report(
    findings: Iterable[Any],
    metadata: Mapping[str, Any] | None = None,
    *,
    sensitive_values: Iterable[str] = (),
) -> bytes:
    """Return a professional PDF report as bytes without writing report files.

    Metadata is allow-listed; only report fields explicitly consumed below are
    included. Credential-like keys in findings/evidence are redacted, and any
    current-session secret values passed by the dashboard are removed.
    """
    secrets = tuple(str(value) for value in sensitive_values if value)
    metadata = _sanitize(metadata or {}, secrets)
    items = [_finding_data(finding, secrets) for finding in findings]
    counts = Counter(_severity(item) for item in items)
    failed_findings = [item for item in items if not item.get("passed")]
    passed_findings = [item for item in items if item.get("passed")]

    report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scan_timestamp = _metadata_value(
        metadata, "scan_timestamp", "timestamp", default=report_time
    )
    region = _metadata_value(metadata, "region", "aws_region")
    account_id = _metadata_value(metadata, "aws_account_id", "account_id")
    duration = _metadata_value(
        metadata, "scan_duration_seconds", "duration_seconds", default=None
    )
    if duration is not None:
        duration = f"{float(duration):.2f} seconds"
    cloudguard_version = _metadata_value(
        metadata, "cloudguard_version", "version", default="v1.0.0"
    )
    plugin_count = _metadata_value(
        metadata, "plugins_executed", "plugin_count", "checks_executed", default=None
    )

    styles = _styles()
    buffer = io.BytesIO()
    document = BaseDocTemplate(
        buffer,
        pagesize=letter,
        title="CloudGuard AWS Cloud Security Assessment Report",
        author="CloudGuard",
        subject="Read-only AWS cloud security assessment",
        leftMargin=46,
        rightMargin=46,
        topMargin=48,
        bottomMargin=48,
    )
    frame = Frame(
        document.leftMargin,
        document.bottomMargin,
        document.width,
        document.height,
        leftPadding=0,
        rightPadding=0,
        topPadding=8,
        bottomPadding=8,
        id="report-frame",
    )
    document.addPageTemplates(PageTemplate(id="report", frames=[frame], onPage=_page_chrome))
    story = []

    story.extend([
        Spacer(1, 0.55 * inch),
        _paragraph("CLOUDGUARD", styles["cover_title"]),
        _paragraph("AWS Cloud Security Assessment Report", styles["cover_subtitle"]),
        Spacer(1, 0.18 * inch),
        _paragraph(PROJECT_NAME, styles["project"]),
        Spacer(1, 0.28 * inch),
    ])
    cover_info = [
        ["Generated", report_time],
        ["AWS Region", region],
        ["AWS Account", account_id],
        ["Assessment Mode", "Read-only"],
    ]
    cover_table = Table(
        [[_paragraph(label, styles["label"]), _paragraph(value, styles["body"])] for label, value in cover_info],
        colWidths=[1.55 * inch, 4.85 * inch],
        hAlign="CENTER",
    )
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.7, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([cover_table, Spacer(1, 0.28 * inch)])
    story.append(_paragraph(
        "This report summarizes read-only checks performed by CloudGuard. "
        "It contains assessment findings and remediation guidance returned by the scanner.",
        styles["body"],
    ))
    story.append(PageBreak())

    story.append(_paragraph("Executive Summary", styles["section"]))
    metric_values = [
        ("Total Findings", len(items)),
        ("Critical", counts["CRITICAL"]),
        ("High", counts["HIGH"]),
        ("Medium", counts["MEDIUM"]),
        ("Low", counts["LOW"]),
        ("Passed Checks", counts["PASS"]),
    ]
    metric_cells = [[
        Table(
            [[_paragraph(value, styles["metric"])], [_paragraph(label, styles["metric_label"])]],
            colWidths=[1.12 * inch],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), PALE),
                ("BOX", (0, 0), (-1, -1), 0.5, GRID),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]),
        )
        for label, value in metric_values
    ]]
    metrics = Table(metric_cells, colWidths=[1.19 * inch] * len(metric_values), hAlign="LEFT")
    metrics.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.extend([metrics, Spacer(1, 8)])

    executive_rows = [
        ("Scan status", _metadata_value(metadata, "scan_status", default="Completed")),
        ("Scan execution time", duration if duration is not None else "Not provided"),
    ]
    executive_table = Table(
        [[_paragraph(label, styles["label"]), _paragraph(value, styles["small"])]
         for label, value in executive_rows],
        colWidths=[1.55 * inch, 5.15 * inch],
        hAlign="LEFT",
    )
    executive_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PALE),
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([executive_table, Spacer(1, 8)])

    summary_rows = [[_paragraph(column, styles["table_header"]) for column in (
        "Finding ID", "Check", "Severity", "Category", "Resource", "Status"
    )]]
    for item in items:
        severity = _severity(item)
        summary_rows.append([
            _paragraph(item.get("finding_id") or "-", styles["small"]),
            _paragraph(item.get("check") or "Unnamed check", styles["small"]),
            _severity_paragraph(severity, styles["small"]),
            _paragraph(item.get("category") or "-", styles["small"]),
            _paragraph(item.get("resource") or "-", styles["small"]),
            _paragraph("PASSED" if item.get("passed") else "FAILED", styles["small"]),
        ])
    summary_table = Table(
        summary_rows,
        colWidths=[0.76 * inch, 1.23 * inch, 0.68 * inch, 0.78 * inch, 2.35 * inch, 0.65 * inch],
        repeatRows=1,
        hAlign="LEFT",
    )
    summary_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for row_index, item in enumerate(items, start=1):
        summary_commands.extend([
            ("BACKGROUND", (0, row_index), (-1, row_index), colors.white if row_index % 2 else PALE),
            ("TEXTCOLOR", (2, row_index), (2, row_index), SEVERITY_COLORS[_severity(item)]),
        ])
    summary_table.setStyle(TableStyle(summary_commands))
    story.extend([
        _paragraph("Findings Summary", styles["subsection"]),
        summary_table,
    ])
    if not items:
        story.append(_paragraph("No findings were returned by the scan.", styles["body"]))
    story.append(_paragraph("Scan Metadata", styles["subsection"]))
    metadata_rows = [
        ("Scan status", _metadata_value(metadata, "scan_status", default="Completed")),
        ("Scan timestamp", scan_timestamp),
        ("Scan duration", duration),
        ("CloudGuard version", cloudguard_version),
    ]
    if plugin_count is not None:
        metadata_rows.append(("Plugins/checks executed", plugin_count))
    meta_table = Table(
        [[_paragraph(label, styles["label"]), _paragraph(value, styles["small"])] for label, value in metadata_rows],
        colWidths=[1.55 * inch, 5.15 * inch],
        hAlign="LEFT",
    )
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PALE),
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)

    if failed_findings:
        story.extend([PageBreak(), _paragraph("Detailed Findings", styles["section"])])
        for item in failed_findings:
            finding_id = item.get("finding_id") or "Finding"
            heading = f"{finding_id} - {item.get('check') or 'Unnamed check'}"
            severity = _severity(item)
            story.extend([
                _paragraph(heading, styles["subsection"]),
                Paragraph(
                    f'Severity: <font color="{SEVERITY_COLORS[severity].hexval()}"><b>{severity}</b></font>',
                    styles["detail_severity"],
                ),
            ])
            detail_rows = [
                ("Category", item.get("category")),
                ("Resource", item.get("resource")),
                ("Issue", item.get("issue")),
                ("Evidence", item.get("evidence")),
                ("Recommendation", item.get("recommendation") or item.get("remediation")),
            ]
            cis_parts = [
                item.get("cis_control"),
                item.get("cis_title"),
                item.get("cis_benchmark"),
                item.get("cis_version"),
                item.get("compliance"),
            ]
            if any(cis_parts):
                detail_rows.append(("CIS reference", [part for part in cis_parts if part]))
            if item.get("risk_score") is not None:
                detail_rows.append(("Risk score", item.get("risk_score")))
            details = Table(
                [[_paragraph(label, styles["label"]), _paragraph(value, styles["small"])]
                 for label, value in detail_rows],
                colWidths=[1.18 * inch, 5.52 * inch],
                hAlign="LEFT",
            )
            details.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), PALE),
                ("GRID", (0, 0), (-1, -1), 0.35, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.extend([details, Spacer(1, 8)])

    if passed_findings:
        story.append(_paragraph("Passed Checks", styles["section"]))
        passed_rows = [[_paragraph(label, styles["table_header"]) for label in (
            "Check", "Category", "Resource"
        )]]
        for item in passed_findings:
            passed_rows.append([
                _paragraph(item.get("check") or "Unnamed check", styles["small"]),
                _paragraph(item.get("category") or "-", styles["small"]),
                _paragraph(item.get("resource") or "-", styles["small"]),
            ])
        passed_table = Table(
            passed_rows,
            colWidths=[2.2 * inch, 1.2 * inch, 3.3 * inch],
            repeatRows=1,
            hAlign="LEFT",
        )
        passed_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
            ("GRID", (0, 0), (-1, -1), 0.4, GRID),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(passed_table)

    recommendations = []
    seen_recommendations = set()
    for item in failed_findings:
        recommendation = item.get("recommendation") or item.get("remediation")
        if recommendation:
            key = json.dumps(recommendation, sort_keys=True, default=str)
            if key not in seen_recommendations:
                seen_recommendations.add(key)
                recommendations.append((item, recommendation))
    if recommendations:
        story.append(_paragraph("Recommendations", styles["section"]))
        for index, (item, recommendation) in enumerate(recommendations, start=1):
            check_name = item.get("check") or "Finding"
            resource = item.get("resource") or "Resource not provided"
            story.append(_paragraph(
                f"{index}. {check_name} - {resource}: {recommendation}", styles["body"]
            ))

    document.build(story)
    return buffer.getvalue()
