"""Native desktop UI for ProjectOSINT (PySide6).

The desktop app is a pure view over the same engine the CLI and web layers
use: it subscribes to the scheduler's progress events, renders them as
per-source status chips, and shows the finished report with the same severity
model, provenance and exports.  No server, no browser, no port - one process,
one window.

Design language is a direct port of the web dashboard: near-black surfaces,
hairline borders, muted steel accent, monospace for data.  Qt's Fusion style
plus a scoped QSS stylesheet; nothing here looks like a default toolkit.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from PySide6.QtCore import QSize, Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListView,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from . import __version__, registry
from .cache import ResultCache
from .config import Settings, load_settings
from .export import write_csv, write_json, write_pdf
from .logging_setup import get_logger, setup_logging
from .models import ScanReport, Target
from .personal import PersonalReport, default_results_dir, parse_emails, run_checks
from .scheduler import ScanEngine
from .store import Store
from .targets import parse_target

PALETTE = {
    "bg": "#0b0c0e",
    "side": "#0e1013",
    "surface": "#14171b",
    "surface2": "#181c21",
    "surface3": "#1d2228",
    "line": "#222831",
    "line_strong": "#2f3641",
    "ink": "#e8eaed",
    "dim": "#a4abb5",
    "faint": "#6f7885",
    "accent": "#a9bfd0",
    "accent_strong": "#c9dceb",
    "ok": "#7fae8b",
    "warn": "#c9a227",
    "err": "#d1666b",
}
SEVERITY_COLOURS = {
    "critical": "#e05a5f",
    "high": "#d97b4f",
    "medium": "#c9a227",
    "low": "#6d9dc5",
    "info": "#8a929d",
}
STATUS_COLOURS = {
    "ok": "#7fae8b",
    "cached": "#a9bfd0",
    "partial": "#c9a227",
    "timeout": "#d1666b",
    "error": "#d1666b",
    "skipped": "#6f7885",
    "running": "#c9a227",
    "pending": "#2f3641",
}
STATUS_TEXT = {
    "ok": "collected",
    "cached": "cached",
    "partial": "partial",
    "timeout": "timeout",
    "error": "error",
    "skipped": "skipped",
}
SEVERITIES = ["critical", "high", "medium", "low", "info"]

SCOPE_NOTICE = (
    "ProjectOSINT performs <b>passive, lawfully-scoped</b> collection only. "
    "Every source queries public, unauthenticated endpoints; robots.txt is "
    "respected, per-host rate limits are enforced, and nothing authenticates, "
    "brute-forces or probes in an intrusive way. "
    "Each query - endpoint, timestamp, rate limit - is written to the "
    "structured log, and every finding carries its provenance. "
    "Run scans only against targets you are authorised to investigate."
)

MONO = "Consolas"
SANS = "Segoe UI"

LICENSE_KEY = "K8QEVB-7V2B54-DPQN9-9OCB1D6-ZVFASTH-MNBK42"

STARTUP_NOTICE = (
    "This is a lawful OSINT application. It does not collect, sell or "
    "transmit your information anywhere. Anything you scan is stored only "
    "on your own device inside the RESULTS folder. Use this tool for "
    "authorised security research and education only. It must never be "
    "used for stalking, harassment, doxxing or any unlawful purpose. By "
    "continuing you confirm you will use it lawfully and with consent."
)

PROBE_BOT_SYSTEM = (
    "You are Probe Bot, the built in assistant for ProjectOSINT, a lawful "
    "OSINT desktop application. Answer questions about using the app, its "
    "collectors, configuration, exports and lawful OSINT methodology. Be "
    "concise and specific. Refuse requests involving doxxing, harassment, "
    "stalking or bypassing other services' authentication."
)

PROBE_BOT_FAQ = (
    "No AI provider configured yet. Add OSINT_PROBE_BOT_API_KEY to the .env "
    "file next to the app (OSINT_PROBE_BOT_BASE_URL and OSINT_PROBE_BOT_MODEL "
    "are optional and default to DeepSeek). Until then I can answer from the "
    "built in guide:\n"
    "  Scan: enter a domain, IP, URL, email or username and press Run scan.\n"
    "  Personal Data: enter your email or username, optionally a password, to\n"
    "    check breaches and public profile presence; reports land in RESULTS.\n"
    "  History: reopen previous scans. Sources: the collector catalog.\n"
    "  Exports: JSON, CSV and PDF buttons on the results view.\n"
    "  Keys: HIBP enables the email breach and paste lookups in .env.\n"
)

PERSONAL_NOTICE = (
    "This Personal Data tab checks whether your email or accounts have "
    "appeared in known data breaches or were traded on dark web markets. "
    "It uses only public lawful sources. Nothing you type leaves this "
    "computer and every result is saved in a RESULTS folder next to the app."
)


# ─────────────────────────────────────────────────────────────────────────
# small shared pieces
# ─────────────────────────────────────────────────────────────────────────

def utcnow() -> datetime:
    return datetime.now(UTC)


def _esc(text: object) -> str:
    return (
        str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _normalise_key(value: str) -> str:
    return "".join(ch for ch in value.upper() if ch.isalnum())


def valid_license_key(value: str) -> bool:
    return bool(value) and _normalise_key(value) == _normalise_key(LICENSE_KEY)


def license_file(settings: Settings) -> Path:
    return settings.data_dir / "license.json"


def license_needed(settings: Settings) -> bool:
    return not license_file(settings).is_file()


def save_license(settings: Settings) -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    license_file(settings).write_text(
        json.dumps({"licensed": True, "accepted_at": utcnow().isoformat()}),
        encoding="utf-8",
    )


def _monogram_icon() -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(PALETTE["surface"]))
    painter.setPen(QColor(PALETTE["line_strong"]))
    painter.drawRoundedRect(1, 1, 62, 62, 12, 12)
    painter.setPen(QColor(PALETTE["accent"]))
    painter.setFont(QFont(MONO, 24, QFont.Weight.Bold))
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "PO")
    painter.end()
    return QIcon(pixmap)


def _qss() -> str:
    p = PALETTE
    return f"""
    * {{ outline: none; }}
    QMainWindow, QWidget {{ background: {p['bg']}; color: {p['ink']}; }}
    QFrame#sidebar {{ background: {p['side']}; border: none; border-right: 1px solid {p['line']}; }}
    QLabel#brand-name {{ font-size: 14px; font-weight: 600; color: {p['ink']}; }}
    QLabel#brand-ver {{ font-size: 10px; color: {p['faint']}; font-family: '{MONO}'; }}
    QLabel#brand-mark {{ color: {p['accent']}; font-family: '{MONO}'; font-size: 11px;
        background: {p['surface']}; border: 1px solid {p['line_strong']}; border-radius: 6px; }}
    QPushButton#nav {{ text-align: left; padding: 7px 10px; border: none; border-radius: 6px;
        background: transparent; color: {p['dim']}; }}
    QPushButton#nav:hover {{ background: {p['surface']}; color: {p['ink']}; }}
    QPushButton#nav:checked {{ background: {p['surface2']}; color: {p['ink']}; font-weight: 600; }}
    QLabel#scope-note {{ color: {p['faint']}; font-size: 11px; }}
    QLabel#stat-k {{ color: {p['faint']}; font-size: 9px; }}
    QLabel#stat-v {{ color: {p['ink']}; font-family: '{MONO}'; font-size: 14px; }}
    QLabel#title {{ font-size: 17px; font-weight: 600; }}
    QLabel#kicker {{ color: {p['faint']}; font-size: 10px; }}
    QFrame#panel, QFrame#summary {{ background: {p['surface']}; border: 1px solid {p['line']};
        border-radius: 6px; }}
    QFrame#detail {{ background: {p['side']}; border: 1px solid {p['line_strong']}; border-radius: 6px; }}
    QLineEdit, QComboBox {{ background: {p['surface']}; border: 1px solid {p['line_strong']};
        border-radius: 6px; padding: 6px 10px; color: {p['ink']};
        selection-background-color: {p['accent']}; selection-color: {p['bg']}; }}
    QLineEdit:focus, QComboBox:focus {{ border: 1px solid {p['accent']}; }}
    QComboBox::drop-down {{ border: none; width: 20px; }}
    QComboBox QAbstractItemView {{ background: {p['surface2']}; color: {p['ink']};
        border: 1px solid {p['line_strong']}; selection-background-color: {p['surface3']}; }}
    QPushButton#run {{ background: {p['ink']}; color: {p['bg']}; font-weight: 600;
        border: none; border-radius: 6px; padding: 8px 20px; }}
    QPushButton#run:hover {{ background: {p['accent_strong']}; }}
    QPushButton#run:disabled {{ background: {p['line_strong']}; color: {p['faint']}; }}
    QPushButton#ghost {{ background: transparent; color: {p['dim']}; border: 1px solid {p['line_strong']};
        border-radius: 6px; padding: 4px 10px; font-family: '{MONO}'; font-size: 11px; }}
    QPushButton#ghost:hover {{ color: {p['ink']}; border-color: {p['accent']}; }}
    QFrame#chip {{ background: {p['side']}; border: 1px solid {p['line']}; border-radius: 5px; }}
    QListWidget#chips {{ background: transparent; border: none; }}
    QTableWidget {{ background: {p['surface']}; color: {p['ink']}; border: 1px solid {p['line']};
        border-radius: 6px; gridline-color: transparent; alternate-background-color: {p['surface2']};
        selection-background-color: {p['surface3']}; selection-color: {p['ink']}; }}
    QTableWidget::item {{ padding: 4px 8px; }}
    QHeaderView::section {{ background: {p['surface2']}; color: {p['faint']}; border: none;
        border-bottom: 1px solid {p['line_strong']}; padding: 8px; font-size: 9px; }}
    QTableCornerButton::section {{ background: {p['surface2']}; border: none; }}
    QScrollBar:vertical {{ background: {p['bg']}; width: 10px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {p['line_strong']}; border-radius: 5px; min-height: 24px; }}
    QScrollBar::handle:vertical:hover {{ background: {p['faint']}; }}
    QScrollBar:horizontal {{ background: {p['bg']}; height: 10px; }}
    QScrollBar::handle:horizontal {{ background: {p['line_strong']}; border-radius: 5px; min-width: 24px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    QStatusBar {{ background: {p['side']}; color: {p['faint']}; border-top: 1px solid {p['line']};
        font-size: 11px; }}
    QToolTip {{ background: {p['surface3']}; color: {p['ink']}; border: 1px solid {p['line_strong']};
        padding: 4px 6px; }}
    QDialog {{ background: {p['bg']}; }}
    QLabel#error {{ color: {p['err']}; font-size: 12px; }}
    QLabel#empty {{ color: {p['faint']}; font-size: 12px; }}
    QTextEdit {{ background: {p['surface']}; color: {p['ink']}; border: 1px solid {p['line_strong']};
        border-radius: 6px; padding: 10px; selection-background-color: {p['surface3']}; }}
    QMessageBox QLabel {{ color: {p['ink']}; }}
    QFrame#notice {{ background: {p['surface']}; border: 1px solid {p['line_strong']};
        border-left: 3px solid {p['accent']}; border-radius: 6px; }}
    QLabel#notice-text {{ color: {p['dim']}; font-size: 12px; background: transparent; }}
    """


def _sev_chip_style(severity: str, checked: bool) -> str:
    colour = SEVERITY_COLOURS[severity]
    if checked:
        return (
            f"QPushButton {{ background: {colour}; color: {PALETTE['bg']}; font-weight: 600; "
            f"border: 1px solid {colour}; border-radius: 5px; padding: 4px 10px; font-size: 10px; }}"
        )
    return (
        f"QPushButton {{ background: transparent; color: {colour}; "
        f"border: 1px solid {PALETTE['line_strong']}; border-radius: 5px; "
        f"padding: 4px 10px; font-size: 10px; }}"
    )


def _mono_font(size: int = 11, bold: bool = False) -> QFont:
    font = QFont(MONO, size)
    font.setWeight(QFont.Weight.Bold if bold else QFont.Weight.Normal)
    return font


def _fmt_ms(ms: float | None) -> str:
    if ms is None:
        return "—"
    return f"{ms / 1000:.2f} s" if ms >= 1000 else f"{ms:.0f} ms"


def _fmt_time(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return iso


# ─────────────────────────────────────────────────────────────────────────
# progress console
# ─────────────────────────────────────────────────────────────────────────

class Chip(QFrame):
    """One collector, one chip: dot + name + count."""

    def __init__(self, name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("chip")
        self.setFixedHeight(26)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(9, 0, 9, 0)
        layout.setSpacing(8)
        self.dot = QLabel()
        self.dot.setFixedSize(6, 6)
        self.dot.setStyleSheet(f"background: {STATUS_COLOURS['pending']}; border-radius: 3px;")
        self.name = QLabel(name)
        self.name.setFont(_mono_font(10))
        self.name.setStyleSheet(f"color: {PALETTE['dim']}; background: transparent;")
        self.count = QLabel("…")
        self.count.setFont(_mono_font(10))
        self.count.setStyleSheet(f"color: {PALETTE['faint']}; background: transparent;")
        layout.addWidget(self.dot)
        layout.addWidget(self.name, 1)
        layout.addWidget(self.count)
        self._status = "pending"

    def set_status(self, status: str, count: int | None = None) -> None:
        self._status = status
        colour = STATUS_COLOURS.get(status, PALETTE["faint"])
        self.dot.setStyleSheet(f"background: {colour}; border-radius: 3px;")
        if count is not None:
            self.count.setText(str(count))
        label = STATUS_TEXT.get(status, status)
        self.setToolTip(f"{self.name.text()}: {label}")


class ChipList(QListWidget):
    """Auto-wrapping grid of collector chips."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("chips")
        self.setViewMode(QListView.ViewMode.IconMode)
        self.setMovement(QListView.Movement.Static)
        self.setResizeMode(QListView.ResizeMode.Adjust)
        self.setFlow(QListView.Flow.LeftToRight)
        self.setWrapping(True)
        self.setSpacing(4)
        self.setGridSize(QSize(178, 30))
        self.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setMaximumHeight(240)
        self._chips: dict[str, Chip] = {}

    def rebuild(self, names: list[str]) -> None:
        self.clear()
        self._chips = {}
        for name in names:
            item = QListWidgetItem()
            chip = Chip(name)
            self.addItem(item)
            self.setItemWidget(item, chip)
            item.setSizeHint(QSize(178, 30))
            self._chips[name] = chip

    def chip(self, name: str) -> Chip | None:
        return self._chips.get(name)


# ─────────────────────────────────────────────────────────────────────────
# provenance detail
# ─────────────────────────────────────────────────────────────────────────

class DetailPanel(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("detail")
        self.setMinimumHeight(96)
        self.setMaximumHeight(190)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        self.label = QLabel()
        self.label.setTextFormat(Qt.TextFormat.RichText)
        self.label.setWordWrap(True)
        self.label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.label)
        self.set_finding(None)

    def set_finding(self, finding: Any) -> None:
        if finding is None:
            self.label.setText(
                f'<span style="color:{PALETTE["faint"]}; font-size:11px">'
                "Select a finding to see its provenance - endpoint, query, "
                "retrieval time, lawful scope and evidence.</span>"
            )
            return
        provenance = finding.provenance
        evidence = finding.evidence or {}
        evidence_text = (
            _esc(json.dumps(evidence, ensure_ascii=False)[:900]) if evidence else "—"
        )
        tags = ", ".join(finding.tags) if finding.tags else "—"

        def row(kicker: str, value: str) -> str:
            return (
                f'<tr><td style="color:{PALETTE["faint"]}; font-size:9px; '
                f"padding:2px 22px 2px 0; vertical-align:top\">{_esc(kicker)}</td>"
                f'<td style="color:{PALETTE["dim"]}; font-family:{MONO}; font-size:11px; '
                f'word-wrap:anywhere\">{value}</td></tr>'
            )

        self.label.setText(
            '<table cellspacing="0" cellpadding="0">'
            + row("ENDPOINT", _esc(provenance.endpoint or "—"))
            + row("QUERY", _esc(provenance.query or "—"))
            + row("RETRIEVED", _esc(_fmt_time(provenance.retrieved_at.isoformat())))
            + row("CONFIDENCE", _esc(finding.confidence.value))
            + row("TAGS", _esc(tags))
            + row("LAWFUL SCOPE", _esc(provenance.terms or "—"))
            + row("EVIDENCE", evidence_text)
            + "</table>"
        )


# ─────────────────────────────────────────────────────────────────────────
# dialogs shown around the main window
# ─────────────────────────────────────────────────────────────────────────

class LicenseDialog(QDialog):
    """Asked once per install: the app is gated behind a license key."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("ProjectOSINT — license key required")
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(12)

        kicker = QLabel("ACTIVATION")
        kicker.setObjectName("kicker")
        title = QLabel("Enter your license key to continue")
        title.setStyleSheet(f"color: {PALETTE['ink']}; font-size: 16px; font-weight: 600;")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("XXXXX-XXXXX-XXXXX-XXXXXXX-XXXXXXX-XXXXXX")
        self.key_input.setFont(_mono_font(11))
        self.key_input.setMinimumHeight(36)
        self.key_input.returnPressed.connect(self._on_activate)
        self.error_label = QLabel("Invalid license key.")
        self.error_label.setObjectName("error")
        self.error_label.hide()
        buttons = QHBoxLayout()
        activate = QPushButton("Activate")
        activate.setObjectName("run")
        activate.setMinimumHeight(36)
        activate.clicked.connect(self._on_activate)
        quit_button = QPushButton("Quit")
        quit_button.setObjectName("ghost")
        quit_button.setMinimumHeight(36)
        quit_button.clicked.connect(self.reject)
        buttons.addWidget(quit_button)
        buttons.addStretch(1)
        buttons.addWidget(activate)

        layout.addWidget(kicker)
        layout.addWidget(title)
        layout.addWidget(self.key_input)
        layout.addWidget(self.error_label)
        layout.addSpacing(6)
        layout.addLayout(buttons)

    def _on_activate(self) -> None:
        if valid_license_key(self.key_input.text()):
            self.accept()
        else:
            self.error_label.show()


class StartupNoticeDialog(QDialog):
    """Shown on every launch, before the main window."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("ProjectOSINT — lawful use notice")
        self.setMinimumWidth(540)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(12)

        kicker = QLabel("READ BEFORE USING")
        kicker.setObjectName("kicker")
        title = QLabel("Lawful, educational use only")
        title.setStyleSheet(f"color: {PALETTE['ink']}; font-size: 16px; font-weight: 600;")
        body = QLabel(STARTUP_NOTICE)
        body.setWordWrap(True)
        body.setStyleSheet(f"color: {PALETTE['dim']}; font-size: 12px; background: transparent;")
        accept = QPushButton("I understand — continue")
        accept.setObjectName("run")
        accept.setMinimumHeight(36)
        accept.clicked.connect(self.accept)

        layout.addWidget(kicker)
        layout.addWidget(title)
        layout.addWidget(body)
        layout.addSpacing(6)
        layout.addWidget(accept)


# ─────────────────────────────────────────────────────────────────────────
# worker threads: the asyncio engine never touches the UI thread
# ─────────────────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    """Runs ScanEngine on its own loop and marshals progress via signals."""

    event_ready = Signal(str, dict)
    finished_report = Signal(object)  # ScanReport
    failed = Signal(str)

    def __init__(
        self,
        settings: Settings,
        target: Target,
        *,
        deadline_s: float,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = settings
        self.target = target
        self.deadline_s = deadline_s

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            report = loop.run_until_complete(self._scan())
            self.finished_report.emit(report)
        except Exception as exc:  # surfaced to the UI, never swallowed
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            loop.close()

    async def _scan(self) -> ScanReport:
        cache: ResultCache | None = None
        if self.settings.cache_ttl_s > 0:
            cache = await ResultCache(
                self.settings.data_dir / "cache.db", self.settings.cache_ttl_s
            ).open()
        try:
            engine = ScanEngine(self.settings, cache=cache, on_event=self._emit)
            report = await engine.scan(self.target, deadline_s=self.deadline_s)
        finally:
            if cache is not None:
                await cache.close()
        async with Store(self.settings.db_path) as store:
            await store.save(report)
        return report

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        self.event_ready.emit(event, payload)


class AsyncWorker(QThread):
    """Run one coroutine-producing callable off the UI thread."""

    result = Signal(object)
    failed = Signal(str)

    def __init__(self, factory: Callable[[], Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._factory = factory

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.result.emit(loop.run_until_complete(self._factory()))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            loop.close()


async def _store_call(settings: Settings, fn: Callable[[Store], Any]) -> Any:
    async with Store(settings.db_path) as store:
        return await fn(store)


class PersonalWorker(QThread):
    """Runs the Personal Data sweep on its own loop; the password is kept
    in this worker's memory only and never written to disk or logs."""

    event_ready = Signal(str, dict)
    finished_report = Signal(object)  # PersonalReport
    failed = Signal(str)

    def __init__(
        self,
        settings: Settings,
        *,
        emails: list[str],
        username: str | None,
        password: str | None,
        deadline_s: float,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = settings
        self.emails = emails
        self.username = username
        self.password = password
        self.deadline_s = deadline_s

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            report = loop.run_until_complete(
                run_checks(
                    self.settings,
                    emails=self.emails,
                    username=self.username,
                    password=self.password,
                    deadline_s=self.deadline_s,
                    on_event=self._emit,
                )
            )
            self.finished_report.emit(report)
        except Exception as exc:  # surfaced to the UI, never swallowed
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            loop.close()

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        self.event_ready.emit(event, payload)


class ProbeBotWorker(QThread):
    """Chats with an OpenAI-compatible API, or answers from the built in FAQ
    when no key is configured (in which case nothing leaves the machine)."""

    reply_ready = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        settings: Settings,
        history: list[dict[str, str]],
        prompt: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = settings
        self.history = history
        self.prompt = prompt

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.reply_ready.emit(loop.run_until_complete(self._ask()))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            loop.close()

    async def _ask(self) -> str:
        if not self.settings.probe_bot_api_key:
            return PROBE_BOT_FAQ
        url = f"{self.settings.probe_bot_base_url.rstrip('/')}/chat/completions"
        messages = [
            {"role": "system", "content": PROBE_BOT_SYSTEM},
            *self.history,
            {"role": "user", "content": self.prompt},
        ]
        async with httpx.AsyncClient(timeout=60.0, verify=self.settings.verify_tls) as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {self.settings.probe_bot_api_key}"},
                json={
                    "model": self.settings.probe_bot_model,
                    "messages": messages,
                    "max_tokens": 600,
                },
            )
        if not response.is_success:
            raise RuntimeError(f"chat provider returned HTTP {response.status_code}")
        data = response.json()
        return str(data["choices"][0]["message"]["content"])


# ─────────────────────────────────────────────────────────────────────────
# main window
# ─────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.settings.ensure_dirs()
        self.log = get_logger("desktop")
        self.report: ScanReport | None = None
        self.worker: ScanWorker | None = None
        self.personal_worker: PersonalWorker | None = None
        self.personal_report: PersonalReport | None = None
        self.bot_worker: ProbeBotWorker | None = None
        self._personal_popup_shown = False
        self._assistants: list[AsyncWorker] = []
        self._rows: list[Any] = []
        self._sev_buttons: dict[str, QPushButton] = {}
        self.active_severities: set[str] = set(SEVERITIES)
        self._chips_total = 0
        self._chips_done = 0
        self._stat_scans: QLabel
        self._stat_findings: QLabel

        self.setWindowTitle(f"ProjectOSINT {__version__} — reconnaissance console")
        self.resize(1260, 840)
        self.setWindowIcon(_monogram_icon())
        self._build_ui()
        self.refresh_stats()

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)

        root_layout.addWidget(self._build_sidebar())

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(28, 24, 28, 18)
        content_layout.setSpacing(14)
        self.title_label = QLabel("New scan")
        self.title_label.setObjectName("title")
        content_layout.addWidget(self.title_label)

        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack, 1)
        self.stack.addWidget(self._build_scan_page())
        self.stack.addWidget(self._build_history_page())
        self.stack.addWidget(self._build_sources_page())
        self.stack.addWidget(self._build_personal_page())
        self.stack.addWidget(self._build_probe_bot_page())
        root_layout.addWidget(content, 1)

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(224)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 20, 16, 16)
        layout.setSpacing(6)

        brand_row = QHBoxLayout()
        mark = QLabel("PO")
        mark.setObjectName("brand-mark")
        mark.setFixedSize(30, 30)
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(1)
        name_label = QLabel("ProjectOSINT")
        name_label.setObjectName("brand-name")
        version_label = QLabel(f"v{__version__} · desktop")
        version_label.setObjectName("brand-ver")
        brand_text.addWidget(name_label)
        brand_text.addWidget(version_label)
        brand_row.addWidget(mark)
        brand_row.addLayout(brand_text, 1)
        layout.addLayout(brand_row)
        layout.addSpacing(20)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self._nav_buttons: dict[str, QPushButton] = {}
        for key, label in (
            ("scan", "Scan"),
            ("personal", "Personal Data"),
            ("history", "History"),
            ("sources", "Sources"),
            ("bot", "Probe Bot"),
        ):
            button = QPushButton(label)
            button.setObjectName("nav")
            button.setCheckable(True)
            button.setMinimumHeight(32)
            button.clicked.connect(lambda _checked=False, page=key: self._show_page(page))
            self.nav_group.addButton(button)
            self._nav_buttons[key] = button
            layout.addWidget(button)
        self._nav_buttons["scan"].setChecked(True)

        layout.addStretch(1)

        scope = QLabel(
            "Passive, lawfully-scoped collection. Every query is logged with "
            "its endpoint, timestamp and rate limit. No authentication is "
            "bypassed."
        )
        scope.setObjectName("scope-note")
        scope.setWordWrap(True)
        layout.addWidget(scope)
        layout.addSpacing(14)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(8)
        for key, label in (("scans", "SCANS"), ("findings", "FINDINGS")):
            box = QVBoxLayout()
            box.setSpacing(2)
            kicker = QLabel(label)
            kicker.setObjectName("stat-k")
            value = QLabel("—")
            value.setObjectName("stat-v")
            box.addWidget(kicker)
            box.addWidget(value)
            setattr(self, f"_stat_{key}", value)
            stats_row.addLayout(box, 1)
        layout.addLayout(stats_row)
        return sidebar

    # -- scan page ------------------------------------------------------
    def _build_scan_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        scan_bar = QHBoxLayout()
        scan_bar.setSpacing(10)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(
            "example.com   ·   8.8.8.8   ·   analyst@example.com   ·   handle"
        )
        self.target_input.setFont(_mono_font(11))
        self.target_input.setMinimumHeight(36)
        self.target_input.returnPressed.connect(self._on_run_clicked)
        self.deadline_combo = QComboBox()
        self.deadline_combo.addItems(["5", "10", "20", "30"])
        self.deadline_combo.setCurrentText("10")
        self.deadline_combo.setMinimumHeight(36)
        self.deadline_combo.setFixedWidth(84)
        self.run_button = QPushButton("Run scan")
        self.run_button.setObjectName("run")
        self.run_button.setMinimumHeight(36)
        self.run_button.clicked.connect(self._on_run_clicked)
        scan_bar.addWidget(self.target_input, 1)
        scan_bar.addWidget(self.deadline_combo)
        scan_bar.addWidget(self.run_button)
        layout.addLayout(scan_bar)

        self.error_label = QLabel()
        self.error_label.setObjectName("error")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        layout.addWidget(self.error_label)

        self.hint = QLabel(
            "Enter a domain, IP address, URL, email or handle. Collectors run "
            "concurrently under one deadline; slow sources degrade to "
            "<i>partial</i> instead of stalling the run."
        )
        self.hint.setObjectName("empty")
        self.hint.setWordWrap(True)
        self.hint.setTextFormat(Qt.TextFormat.RichText)
        self.hint.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.hint, 1)

        # progress console
        self.console = QFrame()
        self.console.setObjectName("panel")
        console_layout = QVBoxLayout(self.console)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.setSpacing(0)
        console_head = QHBoxLayout()
        console_head.setContentsMargins(14, 8, 14, 8)
        kicker = QLabel("COLLECTOR PROGRESS")
        kicker.setObjectName("kicker")
        self.progress_count = QLabel("0 / 0")
        self.progress_count.setFont(_mono_font(10))
        self.progress_count.setStyleSheet(f"color: {PALETTE['faint']};")
        console_head.addWidget(kicker)
        console_head.addStretch(1)
        console_head.addWidget(self.progress_count)
        console_layout.addLayout(console_head)
        self.chips = ChipList()
        console_layout.addWidget(self.chips)
        console_layout.addSpacing(4)
        layout.addWidget(self.console)
        self.console.hide()

        # results
        self.results = QWidget()
        results_layout = QVBoxLayout(self.results)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(10)

        self.summary = QFrame()
        self.summary.setObjectName("summary")
        self.summary_layout = QHBoxLayout(self.summary)
        self.summary_layout.setContentsMargins(16, 10, 16, 10)
        self.summary_layout.setSpacing(26)
        results_layout.addWidget(self.summary)

        filters = QHBoxLayout()
        filters.setSpacing(6)
        self._sev_group = QButtonGroup(self)
        self._sev_group.setExclusive(False)
        for severity in SEVERITIES:
            button = QPushButton(severity.upper())
            button.setCheckable(True)
            button.setChecked(True)
            button.setStyleSheet(_sev_chip_style(severity, True))
            button.clicked.connect(
                lambda _checked=False, sev=severity: self._toggle_severity(sev)
            )
            self._sev_group.addButton(button)
            self._sev_buttons[severity] = button
            filters.addWidget(button)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("filter value, detail, kind")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMinimumHeight(28)
        self.search_input.textChanged.connect(self._render_findings)
        self.source_combo = QComboBox()
        self.source_combo.addItem("all sources")
        self.source_combo.setMinimumHeight(28)
        self.source_combo.setMinimumWidth(150)
        self.source_combo.currentTextChanged.connect(self._render_findings)
        filters.addSpacing(8)
        filters.addWidget(self.search_input, 1)
        filters.addWidget(self.source_combo)
        for text, handler in (("JSON", self.export_json), ("CSV", self.export_csv), ("PDF", self.export_pdf)):
            button = QPushButton(text)
            button.setObjectName("ghost")
            button.setMinimumHeight(28)
            button.clicked.connect(handler)
            filters.addWidget(button)
        results_layout.addLayout(filters)

        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Source", "Kind", "Value", "Detail"])
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.findings_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.findings_table.setShowGrid(False)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setWordWrap(True)
        header = self.findings_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.findings_table.setColumnWidth(0, 92)
        self.findings_table.setColumnWidth(1, 140)
        self.findings_table.setColumnWidth(2, 180)
        self.findings_table.setColumnWidth(3, 330)
        self.findings_table.itemSelectionChanged.connect(self._on_selection)
        results_layout.addWidget(self.findings_table, 1)

        self.detail = DetailPanel()
        results_layout.addWidget(self.detail)
        layout.addWidget(self.results, 1)
        self.results.hide()
        return page

    # -- history / sources ----------------------------------------------
    def _build_history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(
            ["Scan", "Target", "Findings", "Sources", "Started", "Duration"]
        )
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setShowGrid(False)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.cellDoubleClicked.connect(self._open_scan)
        self.history_hint = QLabel("Double-click a scan to reopen it.")
        self.history_hint.setObjectName("empty")
        layout.addWidget(self.history_table, 1)
        layout.addWidget(self.history_hint)
        return page

    def _build_sources_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(["Source", "Category", "Targets", "Weight", "Key", "State"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setStretchLastSection(True)
        table.setColumnWidth(0, 220)
        table.setColumnWidth(1, 130)
        table.setColumnWidth(2, 150)
        table.setColumnWidth(3, 70)
        table.setColumnWidth(4, 90)

        specs = sorted(registry.all_specs(), key=lambda s: (s.category.value, s.name))
        table.setRowCount(len(specs))
        for row, spec in enumerate(specs):
            state = (
                "opt-in"
                if not spec.default_enabled
                else ("key required" if spec.requires_key else "enabled")
            )
            cells = [
                spec.name,
                spec.category.value,
                ", ".join(sorted(k.value for k in spec.target_kinds)),
                spec.weight,
                spec.requires_key or "—",
                state,
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column in {0, 2, 4}:
                    item.setFont(_mono_font(10))
                if column in {1, 3, 5}:
                    item.setForeground(QColor(PALETTE["dim"]))
                table.setItem(row, column, item)
        layout.addWidget(table)
        self.sources_table = table
        return page

    # -- personal data ----------------------------------------------------
    def _build_personal_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        notice = QFrame()
        notice.setObjectName("notice")
        notice_layout = QHBoxLayout(notice)
        notice_layout.setContentsMargins(14, 10, 14, 10)
        notice_text = QLabel(PERSONAL_NOTICE)
        notice_text.setObjectName("notice-text")
        notice_text.setWordWrap(True)
        notice_layout.addWidget(notice_text, 1)
        layout.addWidget(notice)

        form = QHBoxLayout()
        form.setSpacing(10)
        self.personal_email_input = QLineEdit()
        self.personal_email_input.setPlaceholderText("email@example.com, another@example.com")
        self.personal_email_input.setFont(_mono_font(11))
        self.personal_email_input.setMinimumHeight(36)
        self.personal_email_input.returnPressed.connect(self._on_personal_run)
        self.personal_username_input = QLineEdit()
        self.personal_username_input.setPlaceholderText("username (optional)")
        self.personal_username_input.setFont(_mono_font(11))
        self.personal_username_input.setMinimumHeight(36)
        self.personal_username_input.returnPressed.connect(self._on_personal_run)
        self.personal_password_input = QLineEdit()
        self.personal_password_input.setPlaceholderText("password (optional, never stored)")
        self.personal_password_input.setFont(_mono_font(11))
        self.personal_password_input.setMinimumHeight(36)
        self.personal_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.personal_password_input.returnPressed.connect(self._on_personal_run)
        self.personal_deadline_combo = QComboBox()
        self.personal_deadline_combo.addItems(["60", "120", "180", "300"])
        self.personal_deadline_combo.setCurrentText("180")
        self.personal_deadline_combo.setMinimumHeight(36)
        self.personal_deadline_combo.setFixedWidth(84)
        self.personal_run_button = QPushButton("Check personal data")
        self.personal_run_button.setObjectName("run")
        self.personal_run_button.setMinimumHeight(36)
        self.personal_run_button.clicked.connect(self._on_personal_run)
        form.addWidget(self.personal_email_input, 3)
        form.addWidget(self.personal_username_input, 2)
        form.addWidget(self.personal_password_input, 2)
        form.addWidget(self.personal_deadline_combo)
        form.addWidget(self.personal_run_button)
        layout.addLayout(form)

        self.personal_error = QLabel()
        self.personal_error.setObjectName("error")
        self.personal_error.setWordWrap(True)
        self.personal_error.hide()
        layout.addWidget(self.personal_error)

        self.personal_hint = QLabel(
            "Runs the lawful breach checks and a public profile sweep for the "
            "details above. The password is checked with k anonymity: it is "
            "hashed locally and only a 5 character prefix leaves this machine. "
            "Reports land in a RESULTS folder next to the app and nothing is "
            "uploaded anywhere."
        )
        self.personal_hint.setObjectName("empty")
        self.personal_hint.setWordWrap(True)
        self.personal_hint.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.personal_hint, 1)

        self.personal_console = QFrame()
        self.personal_console.setObjectName("panel")
        personal_console_layout = QVBoxLayout(self.personal_console)
        personal_console_layout.setContentsMargins(0, 0, 0, 0)
        personal_console_layout.setSpacing(0)
        personal_head = QHBoxLayout()
        personal_head.setContentsMargins(14, 8, 14, 8)
        personal_kicker = QLabel("PERSONAL CHECK PROGRESS")
        personal_kicker.setObjectName("kicker")
        self.personal_progress = QLabel("0 / 0")
        self.personal_progress.setFont(_mono_font(10))
        self.personal_progress.setStyleSheet(f"color: {PALETTE['faint']};")
        personal_head.addWidget(personal_kicker)
        personal_head.addStretch(1)
        personal_head.addWidget(self.personal_progress)
        personal_console_layout.addLayout(personal_head)
        self.personal_chips = ChipList()
        personal_console_layout.addWidget(self.personal_chips)
        personal_console_layout.addSpacing(4)
        layout.addWidget(self.personal_console)
        self.personal_console.hide()

        self.personal_results = QWidget()
        personal_results_layout = QVBoxLayout(self.personal_results)
        personal_results_layout.setContentsMargins(0, 0, 0, 0)
        personal_results_layout.setSpacing(10)

        self.personal_summary = QFrame()
        self.personal_summary.setObjectName("summary")
        self.personal_summary_layout = QHBoxLayout(self.personal_summary)
        self.personal_summary_layout.setContentsMargins(16, 10, 16, 10)
        self.personal_summary_layout.setSpacing(26)
        personal_results_layout.addWidget(self.personal_summary)

        self.personal_table = QTableWidget(0, 5)
        self.personal_table.setHorizontalHeaderLabels(
            ["Source", "Category", "Status", "Findings", "Detail"]
        )
        self.personal_table.verticalHeader().setVisible(False)
        self.personal_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.personal_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.personal_table.setShowGrid(False)
        self.personal_table.setAlternatingRowColors(True)
        self.personal_table.setWordWrap(True)
        personal_header = self.personal_table.horizontalHeader()
        personal_header.setStretchLastSection(True)
        personal_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.personal_table.setColumnWidth(0, 170)
        self.personal_table.setColumnWidth(1, 110)
        self.personal_table.setColumnWidth(2, 90)
        self.personal_table.setColumnWidth(3, 330)
        personal_results_layout.addWidget(self.personal_table, 1)

        open_button = QPushButton("Open RESULTS folder")
        open_button.setObjectName("ghost")
        open_button.setMinimumHeight(28)
        open_button.clicked.connect(self._open_results_folder)
        local_note = QLabel("Reports are written to the RESULTS folder beside the app. Nothing was uploaded.")
        local_note.setObjectName("empty")
        bottom_row = QHBoxLayout()
        bottom_row.addWidget(open_button)
        bottom_row.addSpacing(10)
        bottom_row.addWidget(local_note, 1)
        personal_results_layout.addLayout(bottom_row)
        layout.addWidget(self.personal_results, 1)
        self.personal_results.hide()
        return page

    def _on_personal_run(self) -> None:
        emails = parse_emails(self.personal_email_input.text())
        username = self.personal_username_input.text().strip() or None
        password = self.personal_password_input.text() or None
        if not emails and not username:
            self._show_personal_error("Enter at least one email or a username.")
            return
        self._show_personal_error(None)
        self.personal_report = None
        self.personal_hint.hide()
        self.personal_results.hide()
        self.personal_console.show()
        self.personal_chips.rebuild([])
        self.personal_progress.setText("0 / 0")
        self._personal_total = 0
        self._personal_done = 0
        self.personal_run_button.setEnabled(False)
        self.personal_password_input.clear()  # never keep it on screen afterwards
        deadline = float(self.personal_deadline_combo.currentText())
        self.personal_worker = PersonalWorker(
            self.settings,
            emails=emails,
            username=username,
            password=password,
            deadline_s=deadline,
            parent=self,
        )
        self.personal_worker.event_ready.connect(self._on_personal_event)
        self.personal_worker.finished_report.connect(self._on_personal_report)
        self.personal_worker.failed.connect(self._on_personal_failed)
        self.personal_worker.start()

    def _on_personal_event(self, event: str, payload: dict[str, Any]) -> None:
        if event == "personal_start":
            self.personal_chips.rebuild(list(payload.get("sources") or []))
            self._personal_total = int(payload.get("total") or 0)
            self._personal_done = 0
            self.personal_progress.setText(f"0 / {self._personal_total}")
        elif event == "source_start":
            chip = self.personal_chips.chip(str(payload.get("source")))
            if chip:
                chip.set_status("running")
        elif event == "source_done":
            self._personal_done += 1
            chip = self.personal_chips.chip(str(payload.get("source")))
            if chip:
                chip.set_status(str(payload.get("status")), int(payload.get("count") or 0))
            done_text = f"{self._personal_done} / {self._personal_total or self._personal_done}"
            self.personal_progress.setText(done_text)

    def _on_personal_report(self, report: PersonalReport) -> None:
        self.personal_report = report
        self.personal_console.hide()
        self.personal_results.show()
        self.personal_run_button.setEnabled(True)
        self._render_personal_summary(report)
        self._render_personal_table(report)
        self.statusBar().showMessage(
            f"personal check {report.scan_id} finished; {len(report.files)} files in RESULTS",
            8000,
        )

    def _on_personal_failed(self, message: str) -> None:
        self._show_personal_error(message)
        self.personal_run_button.setEnabled(True)
        self.personal_console.hide()
        self.personal_hint.show()

    def _show_personal_error(self, message: str | None) -> None:
        if message:
            self.personal_error.setText(message)
            self.personal_error.show()
        else:
            self.personal_error.hide()

    def _render_personal_summary(self, report: PersonalReport) -> None:
        while self.personal_summary_layout.count():
            item = self.personal_summary_layout.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        password_state = "not checked"
        if report.password_checked:
            count = report.password_seen_in_breaches
            password_state = "clean" if count == 0 else f"seen {count} time(s)"
        statuses = "  ·  ".join(f"{key} {value}" for key, value in report.summary.items())
        for key, value in (
            ("EMAILS", ", ".join(report.emails) or "none"),
            ("USERNAME", report.username or "none"),
            ("PASSWORD", password_state),
            ("SOURCES", statuses or "—"),
            ("REPORTS", str(len(report.files))),
        ):
            box = QWidget()
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(0, 0, 0, 0)
            box_layout.setSpacing(2)
            kicker = QLabel(key)
            kicker.setObjectName("stat-k")
            value_label = QLabel(value)
            value_label.setObjectName("stat-v")
            value_label.setFont(_mono_font(10))
            value_label.setToolTip(value)
            box_layout.addWidget(kicker)
            box_layout.addWidget(value_label)
            self.personal_summary_layout.addWidget(box)
        self.personal_summary_layout.addStretch(1)

    def _render_personal_table(self, report: PersonalReport) -> None:
        table = self.personal_table
        table.setRowCount(len(report.results))
        for row_index, result in enumerate(report.results):
            source_item = QTableWidgetItem(result.source)
            source_item.setFont(_mono_font(10))
            category_item = QTableWidgetItem(result.category)
            category_item.setForeground(QColor(PALETTE["dim"]))
            status_item = QTableWidgetItem(result.status.upper())
            status_item.setForeground(
                QColor(STATUS_COLOURS.get(result.status, PALETTE["faint"]))
            )
            status_item.setFont(_mono_font(9, bold=True))
            findings_item = QTableWidgetItem("  |  ".join(result.findings))
            findings_item.setFont(_mono_font(10))
            detail_item = QTableWidgetItem(result.detail or result.error or "")
            detail_item.setForeground(QColor(PALETTE["dim"]))
            table.setItem(row_index, 0, source_item)
            table.setItem(row_index, 1, category_item)
            table.setItem(row_index, 2, status_item)
            table.setItem(row_index, 3, findings_item)
            table.setItem(row_index, 4, detail_item)

    def _open_results_folder(self) -> None:
        directory = default_results_dir()
        if directory.is_dir():
            os.startfile(str(directory))
        else:
            self.statusBar().showMessage(f"no RESULTS folder yet at {directory}", 8000)

    # -- probe bot --------------------------------------------------------
    def _build_probe_bot_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        hint = QLabel(
            "Chat with Probe Bot about ProjectOSINT: how scans work, the "
            "collectors, configuration, exports and lawful OSINT methodology. "
            "Without a configured API key it answers from a built in guide and "
            "nothing is sent anywhere; with a key, your messages go to that "
            "provider only."
        )
        hint.setObjectName("empty")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.bot_display = QTextEdit()
        self.bot_display.setReadOnly(True)
        layout.addWidget(self.bot_display, 1)

        input_row = QHBoxLayout()
        input_row.setSpacing(10)
        self.bot_input = QLineEdit()
        self.bot_input.setPlaceholderText("Ask about the app…")
        self.bot_input.setMinimumHeight(36)
        self.bot_input.returnPressed.connect(self._on_bot_send)
        self.bot_send_button = QPushButton("Send")
        self.bot_send_button.setObjectName("run")
        self.bot_send_button.setMinimumHeight(36)
        self.bot_send_button.clicked.connect(self._on_bot_send)
        input_row.addWidget(self.bot_input, 1)
        input_row.addWidget(self.bot_send_button)
        layout.addLayout(input_row)

        self.bot_history: list[dict[str, str]] = []
        self._render_bot_log()
        return page

    def _on_bot_send(self) -> None:
        if self.bot_worker is not None and self.bot_worker.isRunning():
            return
        text = self.bot_input.text().strip()
        if not text:
            return
        self.bot_history.append({"role": "user", "content": text})
        self.bot_input.clear()
        self._render_bot_log()
        self.bot_send_button.setEnabled(False)
        self.bot_worker = ProbeBotWorker(
            self.settings, history=list(self.bot_history), prompt=text, parent=self
        )
        self.bot_worker.reply_ready.connect(self._on_bot_reply)
        self.bot_worker.failed.connect(self._on_bot_failed)
        self.bot_worker.start()

    def _on_bot_reply(self, reply: str) -> None:
        self.bot_history.append({"role": "assistant", "content": reply})
        self.bot_send_button.setEnabled(True)
        self._render_bot_log()

    def _on_bot_failed(self, message: str) -> None:
        self.bot_history.append({"role": "assistant", "content": f"(error) {message}"})
        self.bot_send_button.setEnabled(True)
        self._render_bot_log()

    def _render_bot_log(self) -> None:
        parts: list[str] = []
        for entry in self.bot_history[-50:]:
            label = "YOU" if entry["role"] == "user" else "PROBE BOT"
            colour = PALETTE["accent"] if entry["role"] == "user" else PALETTE["ink"]
            body = _esc(entry["content"]).replace("\n", "<br>")
            parts.append(
                f'<div style="margin:6px 0">'
                f'<span style="color:{PALETTE["faint"]}; font-size:9px">{_esc(label)}</span><br>'
                f'<span style="color:{colour}">{body}</span></div>'
            )
        if parts:
            self.bot_display.setHtml("".join(parts))
        else:
            self.bot_display.setHtml(
                f'<span style="color:{PALETTE["faint"]}">'
                "Probe Bot is ready. Ask anything about using ProjectOSINT.</span>"
            )
        scrollbar = self.bot_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    # ------------------------------------------------------------------
    def _show_page(self, page: str) -> None:
        self.stack.setCurrentIndex(
            {"scan": 0, "history": 1, "sources": 2, "personal": 3, "bot": 4}[page]
        )
        self.title_label.setText(
            {
                "scan": "New scan",
                "history": "Scan history",
                "sources": "Collector catalog",
                "personal": "Personal data",
                "bot": "Probe Bot",
            }[page]
        )
        if page == "history":
            self.load_history()
        if page == "personal" and not self._personal_popup_shown:
            # once per session, on first entry - not on every tab open
            self._personal_popup_shown = True
            QMessageBox.information(self, "Personal Data", PERSONAL_NOTICE)

    # -- scan lifecycle -------------------------------------------------
    def _on_run_clicked(self) -> None:
        target_text = self.target_input.text().strip()
        if not target_text:
            self._show_error("Enter a target first.")
            return
        try:
            target = parse_target(target_text)
        except ValueError as exc:
            self._show_error(str(exc))
            return
        self._show_error(None)
        self.report = None
        self.active_severities = set(SEVERITIES)
        self.hint.hide()
        self.results.hide()
        self.console.show()
        self.chips.rebuild([])
        self._chips_total = 0
        self._chips_done = 0
        self.progress_count.setText("0 / 0")
        self.run_button.setEnabled(False)
        self.statusBar().showMessage(f"scanning {target.label} …")

        deadline = float(self.deadline_combo.currentText())
        self.worker = ScanWorker(self.settings, target, deadline_s=deadline, parent=self)
        self.worker.event_ready.connect(self._on_event)
        self.worker.finished_report.connect(self._on_report)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    def _on_event(self, event: str, payload: dict[str, Any]) -> None:
        if event == "scan_start":
            sources = list(payload.get("sources") or [])
            self.chips.rebuild(sources)
            self._chips_total = len(sources)
            self._chips_done = 0
            self.progress_count.setText(f"0 / {len(sources)}")
        elif event == "source_start":
            chip = self.chips.chip(str(payload.get("source")))
            if chip:
                chip.set_status("running")
        elif event == "source_done":
            self._chips_done += 1
            chip = self.chips.chip(str(payload.get("source")))
            if chip:
                chip.set_status(str(payload.get("status")), int(payload.get("count") or 0))
            self.progress_count.setText(f"{self._chips_done} / {self._chips_total or self._chips_done}")
        elif event == "scan_done":
            self.statusBar().showMessage(
                f"scan {payload.get('scan_id')}: {payload.get('findings')} findings in "
                f"{payload.get('duration_ms', 0):.0f} ms",
                8000,
            )

    def _on_report(self, report: ScanReport) -> None:
        self.log.info("desktop scan {id}: {n} findings", id=report.scan_id, n=report.stats.total_findings)
        self._display_report(report)
        self.run_button.setEnabled(True)
        self.refresh_stats()

    def _on_failed(self, message: str) -> None:
        self._show_error(message)
        self.run_button.setEnabled(True)
        self.console.hide()
        self.hint.show()

    def _show_error(self, message: str | None) -> None:
        if message:
            self.error_label.setText(message)
            self.error_label.show()
        else:
            self.error_label.hide()

    def _display_report(self, report: ScanReport) -> None:
        self.report = report
        self.target_input.setText(report.target.value)
        self.console.hide()
        self.hint.hide()
        self.results.show()
        self.active_severities = set(SEVERITIES)
        self.search_input.setText("")
        self._render_summary(report)
        self._render_severity_buttons(report)
        self._render_source_combo(report)
        self._render_findings()

    # -- results rendering -----------------------------------------------
    def _render_summary(self, report: ScanReport) -> None:
        while self.summary_layout.count():
            item = self.summary_layout.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        stats = report.stats
        statuses = "  ·  ".join(
            f"{STATUS_TEXT.get(key, key)} {value}" for key, value in stats.by_status.items()
        )
        for key, value in (
            ("TARGET", report.target.value),
            ("FINDINGS", str(stats.total_findings)),
            ("SOURCES", str(stats.sources_total)),
            ("DURATION", _fmt_ms(report.duration_ms)),
            ("HTTP", str(stats.http_calls)),
            ("STATUS", statuses or "—"),
        ):
            box = QWidget()
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(0, 0, 0, 0)
            box_layout.setSpacing(2)
            kicker = QLabel(key)
            kicker.setObjectName("stat-k")
            value_label = QLabel(value)
            value_label.setObjectName("stat-v")
            value_label.setFont(_mono_font(10))
            value_label.setToolTip(value)
            box_layout.addWidget(kicker)
            box_layout.addWidget(value_label)
            self.summary_layout.addWidget(box)
        self.summary_layout.addStretch(1)

    def _render_severity_buttons(self, report: ScanReport) -> None:
        counts = report.stats.by_severity
        for severity in SEVERITIES:
            button = self._sev_buttons[severity]
            checked = severity in self.active_severities
            button.setChecked(checked)
            button.setText(f"{severity.upper()} {counts.get(severity, 0)}")
            button.setStyleSheet(_sev_chip_style(severity, checked))

    def _render_source_combo(self, report: ScanReport) -> None:
        self.source_combo.blockSignals(True)
        self.source_combo.clear()
        self.source_combo.addItem("all sources")
        self.source_combo.addItems(sorted({result.source for result in report.results}))
        self.source_combo.blockSignals(False)

    def _toggle_severity(self, severity: str) -> None:
        if severity in self.active_severities:
            self.active_severities.discard(severity)
        else:
            self.active_severities.add(severity)
        self._render_findings()

    def _filtered_rows(self) -> list[Any]:
        if self.report is None:
            return []
        query = self.search_input.text().strip().lower()
        selected = self.source_combo.currentText()
        rows: list[Any] = []
        for finding in self.report.findings:
            if finding.severity.value not in self.active_severities:
                continue
            if selected not in ("", "all sources") and finding.source != selected:
                continue
            if query and not (
                query in finding.value.lower()
                or query in finding.kind.lower()
                or query in finding.source.lower()
                or query in (finding.detail or "").lower()
            ):
                continue
            rows.append(finding)
        return rows

    def _render_findings(self) -> None:
        table = self.findings_table
        table.setRowCount(0)
        self._rows = []
        self.detail.set_finding(None)
        if self.report is None:
            return
        rows = self._filtered_rows()
        shown = rows[:800]
        table.setRowCount(len(shown))
        for row_index, finding in enumerate(shown):
            severity_item = QTableWidgetItem(finding.severity.value.upper())
            severity_item.setForeground(QColor(SEVERITY_COLOURS[finding.severity.value]))
            severity_item.setFont(_mono_font(9, bold=True))
            source_item = QTableWidgetItem(finding.source)
            source_item.setFont(_mono_font(10))
            source_item.setForeground(QColor(PALETTE["dim"]))
            kind_item = QTableWidgetItem(finding.kind)
            kind_item.setFont(_mono_font(10))
            kind_item.setForeground(QColor(PALETTE["dim"]))
            value_item = QTableWidgetItem(finding.value)
            value_item.setFont(_mono_font(10))
            detail_item = QTableWidgetItem(finding.detail or "")
            detail_item.setForeground(QColor(PALETTE["dim"]))
            table.setItem(row_index, 0, severity_item)
            table.setItem(row_index, 1, source_item)
            table.setItem(row_index, 2, kind_item)
            table.setItem(row_index, 3, value_item)
            table.setItem(row_index, 4, detail_item)
        self._rows = shown

    def _on_selection(self) -> None:
        row = self.findings_table.currentRow()
        if 0 <= row < len(self._rows):
            self.detail.set_finding(self._rows[row])
        else:
            self.detail.set_finding(None)

    # -- exports ---------------------------------------------------------
    def _export(self, fmt: str) -> None:
        if self.report is None:
            return
        default = str(Path.cwd() / f"{self.report.scan_id}.{fmt}")
        path, _selected = QFileDialog.getSaveFileName(
            self, f"Export {fmt.upper()}", default, f"{fmt.upper()} files (*.{fmt})"
        )
        if not path:
            return
        try:
            {"json": write_json, "csv": write_csv, "pdf": write_pdf}[fmt](self.report, path)
            self.statusBar().showMessage(f"wrote {path}", 8000)
        except OSError as exc:
            self.statusBar().showMessage(f"export failed: {exc}", 8000)

    def export_json(self) -> None:
        self._export("json")

    def export_csv(self) -> None:
        self._export("csv")

    def export_pdf(self) -> None:
        self._export("pdf")

    # -- history & stats --------------------------------------------------
    def load_history(self) -> None:
        def factory() -> Any:
            return _store_call(self.settings, lambda store: store.list_scans(limit=100))

        self._spawn(factory, self._on_history)

    def _on_history(self, scans: list[dict[str, Any]]) -> None:
        self.history_table.setRowCount(len(scans))
        self.history_hint.setText(
            "Double-click a scan to reopen it." if scans else "No stored scans yet."
        )
        for row, scan in enumerate(scans):
            values = [
                scan["scan_id"],
                scan["target_value"],
                str(scan["findings_total"]),
                str(scan["sources_total"]),
                _fmt_time(scan["started_at"]),
                _fmt_ms(scan["duration_ms"]),
            ]
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                if column in {0, 2, 3, 5}:
                    item.setFont(_mono_font(10))
                if column in {2, 3, 5}:
                    item.setForeground(QColor(PALETTE["dim"]))
                self.history_table.setItem(row, column, item)

    def _open_scan(self, row: int, _column: int) -> None:
        item = self.history_table.item(row, 0)
        if item is None:
            return
        scan_id = item.text()

        def factory() -> Any:
            return _store_call(self.settings, lambda store: store.get(scan_id))

        def on_report(report: ScanReport | None) -> None:
            if report is None:
                self.statusBar().showMessage(f"scan {scan_id} not found", 6000)
                return
            self._display_report(report)
            self._nav_buttons["scan"].setChecked(True)
            self.stack.setCurrentIndex(0)
            self.statusBar().showMessage(f"opened scan {scan_id}", 6000)

        self._spawn(factory, on_report)

    def refresh_stats(self) -> None:
        self._spawn(
            lambda: _store_call(self.settings, lambda store: store.stats()),
            self._on_stats,
        )

    def _on_stats(self, stats: dict[str, Any]) -> None:
        self._stat_scans.setText(str(stats.get("scans", 0)))
        self._stat_findings.setText(str(stats.get("findings", 0)))

    def _spawn(
        self,
        factory: Callable[[], Any],
        on_result: Callable[[Any], None],
    ) -> None:
        worker = AsyncWorker(factory, parent=self)
        worker.result.connect(on_result)
        worker.failed.connect(
            lambda message: self.statusBar().showMessage(f"background task failed: {message}", 8000)
        )
        self._assistants.append(worker)
        worker.finished.connect(lambda: self._assistants.remove(worker))
        worker.start()

    # ------------------------------------------------------------------
    def closeEvent(self, event: Any) -> None:  # noqa: N802 - Qt API
        if self.worker is not None and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait(1000)
        if self.personal_worker is not None and self.personal_worker.isRunning():
            self.personal_worker.terminate()
            self.personal_worker.wait(1000)
        if self.bot_worker is not None and self.bot_worker.isRunning():
            self.bot_worker.terminate()
            self.bot_worker.wait(1000)
        for assistant in self._assistants:
            if assistant.isRunning():
                assistant.wait(1000)
        super().closeEvent(event)


# ─────────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None, settings: Settings | None = None) -> int:
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("ProjectOSINT")
    app.setStyle("Fusion")
    settings = settings or load_settings()
    settings.ensure_dirs()
    setup_logging(settings.log_level, json_logs=settings.log_json, log_dir=settings.data_dir / "logs")
    app.setFont(QFont(SANS, 9))
    app.setStyleSheet(_qss())

    if os.environ.get("OSINT_SKIP_NOTICES") != "1":
        if license_needed(settings):
            license_dialog = LicenseDialog()
            if license_dialog.exec() != QDialog.DialogCode.Accepted:
                return 0
            save_license(settings)
        notice = StartupNoticeDialog()
        if notice.exec() != QDialog.DialogCode.Accepted:
            return 0

    window = MainWindow(settings)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
