"""Report export: JSON (lossless), CSV (analysis), PDF (hand-off).

Every format carries provenance - source, endpoint, retrieval time and the
lawful scope note - because a finding without provenance is a rumour.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import ScanReport, Severity

_SEVERITY_HEX = {
    Severity.CRITICAL: "#b3123e",
    Severity.HIGH: "#c2410c",
    Severity.MEDIUM: "#a16207",
    Severity.LOW: "#0369a1",
    Severity.INFO: "#4b5563",
}

CSV_COLUMNS = (
    "scan_id",
    "target_kind",
    "target_value",
    "source",
    "category",
    "kind",
    "value",
    "detail",
    "severity",
    "confidence",
    "tags",
    "endpoint",
    "query",
    "retrieved_at",
    "lawful_note",
)


def to_dict(report: ScanReport) -> dict[str, Any]:
    return report.model_dump(mode="json")


def to_json(report: ScanReport, *, indent: int = 2) -> str:
    return json.dumps(to_dict(report), indent=indent, ensure_ascii=False)


def write_json(report: ScanReport, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(to_json(report), encoding="utf-8")
    return destination


def to_csv(report: ScanReport) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), lineterminator="\n")
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(
            {
                "scan_id": report.scan_id,
                "target_kind": report.target.kind.value,
                "target_value": report.target.value,
                "source": finding.source,
                "category": finding.category.value,
                "kind": finding.kind,
                "value": finding.value,
                "detail": finding.detail,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "tags": "|".join(finding.tags),
                "endpoint": finding.provenance.endpoint or "",
                "query": finding.provenance.query or "",
                "retrieved_at": finding.provenance.retrieved_at.isoformat(),
                "lawful_note": finding.provenance.terms or "",
            }
        )
    return buffer.getvalue()


def write_csv(report: ScanReport, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(to_csv(report), encoding="utf-8")
    return destination


def _para(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def write_pdf(report: ScanReport, path: str | Path, *, max_rows: int = 400) -> Path:
    """Render a restrained, typography-first PDF report."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    title = ParagraphStyle("TitleX", parent=styles["Title"], fontName="Helvetica-Bold",
                           fontSize=20, leading=24, spaceAfter=2, textColor=colors.HexColor("#111827"))
    meta = ParagraphStyle("MetaX", parent=styles["Normal"], fontName="Helvetica",
                          fontSize=8.5, leading=12, textColor=colors.HexColor("#6b7280"))
    h2 = ParagraphStyle("H2X", parent=styles["Heading2"], fontName="Helvetica-Bold",
                        fontSize=11, leading=14, spaceBefore=12, spaceAfter=4,
                        textColor=colors.HexColor("#111827"))
    body = ParagraphStyle("BodyX", parent=styles["Normal"], fontName="Helvetica",
                          fontSize=8, leading=10, textColor=colors.HexColor("#1f2937"))
    small = ParagraphStyle("SmallX", parent=body, fontSize=7.2, leading=9,
                           textColor=colors.HexColor("#4b5563"))

    doc = SimpleDocTemplate(
        str(destination),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"ProjectOSINT report {report.target.value}",
        author="ProjectOSINT",
    )
    story: list[Any] = [
        _para("OSINT report", title),
        _para(
            f"Target {report.target.kind.value}: {report.target.value} &nbsp;·&nbsp; "
            f"scan {report.scan_id} &nbsp;·&nbsp; {report.started_at:%Y-%m-%d %H:%M} UTC "
            f"&nbsp;·&nbsp; {report.duration_ms:.0f} ms",
            meta,
        ),
        Spacer(1, 6),
    ]

    summary = [
        ["Findings", str(report.stats.total_findings)],
        ["Sources run", str(report.stats.sources_total)],
        ["By status", ", ".join(f"{k}={v}" for k, v in report.stats.by_status.items()) or "-"],
        ["By severity", ", ".join(f"{k}={v}" for k, v in report.stats.by_severity.items()) or "-"],
        ["HTTP requests", str(report.stats.http_calls)],
    ]
    table = Table(summary, colWidths=[32 * mm, 132 * mm])
    table.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 8),
                ("FONT", (1, 0), (1, -1), "Helvetica", 8),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#e5e7eb")),
            ]
        )
    )
    story.append(table)

    story.append(_para("Sources", h2))
    source_rows = [["Source", "Status", "Findings", "ms", "Note"]]
    for result in report.results:
        source_rows.append(
            [
                result.source,
                result.status.value,
                str(result.count),
                f"{result.duration_ms:.0f}",
                (result.error or result.note or "")[:70],
            ]
        )
    source_table = Table(source_rows, colWidths=[38 * mm, 18 * mm, 18 * mm, 14 * mm, 76 * mm], repeatRows=1)
    source_table.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 7.5),
                ("FONT", (0, 1), (-1, -1), "Helvetica", 7.2),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#374151")),
                ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#9ca3af")),
                ("GRID", (0, 1), (-1, -1), 0.2, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    story.append(source_table)

    story.append(_para("Findings", h2))
    rows: list[list[Any]] = [["Severity", "Source", "Kind", "Value", "Detail"]]
    shown = report.findings[:max_rows]
    for finding in shown:
        rows.append(
            [
                _para(finding.severity.value, body),
                _para(finding.source, body),
                _para(finding.kind, body),
                _para(finding.value[:90], small),
                _para(finding.detail[:110], small),
            ]
        )
    findings_table = Table(rows, colWidths=[16 * mm, 28 * mm, 32 * mm, 48 * mm, 40 * mm], repeatRows=1)
    style = [
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 7.5),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#9ca3af")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]
    for index, finding in enumerate(shown, start=1):
        style.append(("TEXTCOLOR", (0, index), (0, index), colors.HexColor(_SEVERITY_HEX[finding.severity])))
    findings_table.setStyle(TableStyle(style))
    story.append(findings_table)
    if len(report.findings) > len(shown):
        story.append(Spacer(1, 4))
        omitted = len(report.findings) - len(shown)
        story.append(_para(f"{omitted} further findings omitted; see CSV/JSON.", small))

    if report.notes:
        story.append(_para("Run notes", h2))
        for note in report.notes:
            story.append(_para(f"· {note}", small))

    story.append(Spacer(1, 8))
    story.append(
        _para(
            "Provenance: every finding above was retrieved from the endpoint recorded in the "
            "JSON/CSV export at the stated time, under the lawful-scope note for its source. "
            "Passive sources only; no authentication bypass, no intrusive probing.",
            small,
        )
    )
    doc.build(story)
    return destination


def write_report(report: ScanReport, *, json_path: str | None = None, csv_path: str | None = None,
                 pdf_path: str | None = None) -> list[Path]:
    written: list[Path] = []
    if json_path:
        written.append(write_json(report, json_path))
    if csv_path:
        written.append(write_csv(report, csv_path))
    if pdf_path:
        written.append(write_pdf(report, pdf_path))
    return written
