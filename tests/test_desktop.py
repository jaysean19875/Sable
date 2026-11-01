"""Desktop UI tests.

Runs Qt on the offscreen platform with a synthetic engine: the whole scan
lifecycle - chips, summary, filters, provenance, exports, history - is
exercised without any network or display.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import httpx
import pytest
import respx
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QLabel, QLineEdit

import projectosint.desktop as desktop
from projectosint import registry
from projectosint.desktop import (
    PERSONAL_NOTICE,
    STARTUP_NOTICE,
    LicenseDialog,
    MainWindow,
    ProbeBotWorker,
    StartupNoticeDialog,
    license_needed,
    save_license,
    valid_license_key,
)
from projectosint.models import (
    Category,
    CollectorResult,
    Confidence,
    Finding,
    Provenance,
    ScanReport,
    Severity,
    Status,
)
from projectosint.personal import PersonalReport, PersonalSourceResult
from projectosint.store import Store
from projectosint.targets import parse_target


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


def _wait(qapp: QApplication, predicate: Callable[[], bool], timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qapp.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return False


class FakeEngine:
    """Same constructor surface as ScanEngine, zero network."""

    def __init__(self, settings, *, cache=None, on_event=None) -> None:
        self.on_event = on_event

    async def scan(self, subject, *, deadline_s=None, sources=None, categories=None,
                   use_cache=True, scan_id=None) -> ScanReport:
        target = subject if hasattr(subject, "kind") else parse_target(str(subject))
        report = ScanReport(target=target, scan_id=scan_id or "fakedesktop")
        finding = Finding.build(
            source="fake_source",
            category=Category.WEB,
            kind="web.title",
            value="Example Domain",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            provenance=Provenance(
                source="fake_source", category=Category.WEB, endpoint="https://example.com/"
            ),
        )
        report.results = [
            CollectorResult(
                source="fake_source", category=Category.WEB, status=Status.OK,
                findings=[finding], duration_ms=4.0,
            )
        ]
        report.findings = [finding]
        if self.on_event:
            self.on_event("scan_start", {"scan_id": report.scan_id, "target": target.label,
                                         "sources": ["fake_source"], "deadline_s": 5})
            self.on_event("source_done", {"source": "fake_source", "status": "ok",
                                          "count": 1, "duration_ms": 4.0})
        report.finalise()
        if self.on_event:
            self.on_event("scan_done", {"scan_id": report.scan_id, "target": target.label,
                                        "duration_ms": report.duration_ms, "findings": 1})
        return report


def seed_report(scan_id: str) -> ScanReport:
    target = parse_target("example.com")
    finding = Finding.build(
        source="dns_a",
        category=Category.DNS,
        kind="dns.a",
        value="93.184.216.34",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        provenance=Provenance(source="dns_a", category=Category.DNS, endpoint="DNS A example.com"),
    )
    report = ScanReport(target=target, scan_id=scan_id)
    report.results = [
        CollectorResult(source="dns_a", category=Category.DNS, status=Status.OK,
                        findings=[finding], duration_ms=3.0)
    ]
    report.findings = [finding]
    return report.finalise()


# ─────────────────────────────────────────────────────────────────────────

def test_license_flow(settings) -> None:
    assert license_needed(settings) is True
    save_license(settings)
    assert license_needed(settings) is False
    payload = json.loads(desktop.license_file(settings).read_text(encoding="utf-8"))
    assert payload["licensed"] is True


def test_license_key_validation() -> None:
    assert valid_license_key("K8QEVB-7V2B54-DPQN9-9OCB1D6-ZVFASTH-MNBK42") is True
    assert valid_license_key("k8qevb7v2b54dpqn99ocb1d6zvfasthmnbk42") is True
    assert valid_license_key("WRONG-KEY-0000") is False
    assert valid_license_key("") is False


def test_license_dialog_rejects_bad_key(qapp: QApplication) -> None:
    dialog = LicenseDialog()
    dialog.key_input.setText("nope")
    dialog._on_activate()
    assert not dialog.error_label.isHidden()
    assert dialog.result() != QDialog.DialogCode.Accepted
    dialog.key_input.setText("K8QEVB-7V2B54-DPQN9-9OCB1D6-ZVFASTH-MNBK42")
    dialog._on_activate()
    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.close()


def test_startup_notice_text_bounds() -> None:
    assert len(STARTUP_NOTICE.split()) <= 80
    assert "-" not in STARTUP_NOTICE
    assert "doxxing" in STARTUP_NOTICE


def test_startup_dialog_shows_notice(qapp: QApplication) -> None:
    dialog = StartupNoticeDialog()
    labels = [label.text() for label in dialog.findChildren(QLabel)]
    assert STARTUP_NOTICE in labels
    dialog.close()


def test_window_constructs(qapp: QApplication, settings) -> None:
    window = MainWindow(settings)
    assert len(window._nav_buttons) == 5
    assert window.stack.count() == 5
    assert window.sources_table.rowCount() == len(registry.all_specs())
    assert window.sources_table.rowCount() >= 25
    window.close()


def test_personal_popup_once_per_session(
    qapp: QApplication, settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def fake_information(parent, title, text):
        calls.append(text)

    monkeypatch.setattr(desktop.QMessageBox, "information", staticmethod(fake_information))
    window = MainWindow(settings)
    assert window._personal_popup_shown is False
    window._show_page("personal")
    assert window._personal_popup_shown is True
    assert calls == [desktop.PERSONAL_NOTICE]
    window._show_page("history")
    window._show_page("personal")  # second entry in the same session: no popup
    assert len(calls) == 1
    window.close()


def test_scan_lifecycle_renders_results(
    qapp: QApplication, settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(desktop, "ScanEngine", FakeEngine)
    window = MainWindow(settings)
    window.target_input.setText("example.com")
    window._on_run_clicked()

    worker = window.worker
    assert worker is not None
    assert worker.wait(8000), "scan worker did not finish"

    assert _wait(qapp, lambda: window.findings_table.rowCount() == 1), "findings table never filled"
    assert window.run_button.isEnabled()
    assert window.error_label.isHidden()
    assert window.console.isHidden()
    assert not window.results.isHidden()

    chip = window.chips.chip("fake_source")
    assert chip is not None
    assert chip._status == "ok"

    # summary shows the finding count
    summary_labels = window.summary.findChildren(QLabel)
    assert any(label.text() == "1" for label in summary_labels)

    # severity filter toggles the table
    low_button = window._sev_buttons["low"]
    low_button.click()
    assert _wait(qapp, lambda: window.findings_table.rowCount() == 0)
    low_button.click()
    assert _wait(qapp, lambda: window.findings_table.rowCount() == 1)

    # search filter
    window.search_input.setText("does-not-match")
    assert _wait(qapp, lambda: window.findings_table.rowCount() == 0)
    window.search_input.setText("")
    assert _wait(qapp, lambda: window.findings_table.rowCount() == 1)

    # selecting a row shows provenance
    window.findings_table.selectRow(0)
    qapp.processEvents()
    assert "endpoint" in window.detail.label.text().lower()

    window.close()


def test_export_writes_file(
    qapp: QApplication, settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(desktop, "ScanEngine", FakeEngine)
    window = MainWindow(settings)
    window.target_input.setText("example.com")
    window._on_run_clicked()
    assert window.worker is not None and window.worker.wait(8000)
    assert _wait(qapp, lambda: window.report is not None)

    target_path = str(tmp_path / "report.json")
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *args, **kwargs: (target_path, "JSON (*.json)")),
    )
    window.export_json()
    payload = json.loads(Path(target_path).read_text(encoding="utf-8"))
    assert payload["scan_id"] == "fakedesktop"
    window.close()


def test_history_and_reopen(qapp: QApplication, settings) -> None:
    report = seed_report("desktophist")
    asyncio.run(_save(settings, report))

    window = MainWindow(settings)
    window.load_history()
    assert _wait(qapp, lambda: window.history_table.rowCount() >= 1), "history never loaded"
    assert window.history_table.item(0, 0).text() == "desktophist"

    window._open_scan(0, 0)
    assert _wait(qapp, lambda: window.findings_table.rowCount() == 1), "reopened report not shown"
    assert window.stack.currentIndex() == 0
    assert window.target_input.text() == "example.com"
    window.close()


async def _save(settings, report: ScanReport) -> None:
    async with Store(settings.db_path) as store:
        await store.save(report)


async def _fake_run_checks(settings, *, emails, username, password, deadline_s,
                           results_dir=None, on_event=None) -> PersonalReport:
    """Same call shape as projectosint.personal.run_checks, zero network."""
    if on_event:
        on_event("personal_start", {"scan_id": "pdtest", "total": 2,
                                    "sources": ["check_a · email", "check_b · user"]})
        on_event("source_done", {"source": "check_a · email", "status": "ok", "count": 1})
        on_event("source_done", {"source": "check_b · user", "status": "skipped", "count": 0})
    report = PersonalReport(
        scan_id="pdtest",
        emails=emails,
        username=username,
        password_checked=password is not None,
        password_seen_in_breaches=3 if password else None,
        results=[
            PersonalSourceResult(source="check_a", category="exposure", status="ok",
                                 count=1, findings=["test.kind: 1"]),
            PersonalSourceResult(source="check_b", category="exposure", status="skipped",
                                 detail="needs key"),
        ],
        files=["pdtest_personal.json", "pdtest_personal.csv", "pdtest_personal.txt"],
    )
    if on_event:
        on_event("personal_done", {"scan_id": "pdtest", "files": report.files, "summary": {}})
    return report


def test_personal_page_has_notice_and_masked_password(qapp: QApplication, settings) -> None:
    window = MainWindow(settings)
    assert "personal" in window._nav_buttons
    labels = [label.text() for label in window.findChildren(QLabel)]
    assert PERSONAL_NOTICE in labels
    assert window.personal_password_input.echoMode() is QLineEdit.EchoMode.Password
    window.close()


def test_personal_run_flow_renders_results(
    qapp: QApplication, settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(desktop, "run_checks", _fake_run_checks)
    window = MainWindow(settings)
    window.personal_email_input.setText("analyst@example.com")
    window.personal_username_input.setText("analyst")
    window.personal_password_input.setText("pw123")
    window._on_personal_run()

    worker = window.personal_worker
    assert worker is not None
    assert worker.wait(8000), "personal worker did not finish"
    assert _wait(qapp, lambda: window.personal_table.rowCount() == 2)

    assert window.personal_password_input.text() == ""  # cleared from the widget
    assert window.personal_run_button.isEnabled()
    assert not window.personal_results.isHidden()
    assert window.personal_chips.chip("check_a · email") is not None
    summary_labels = [label.text() for label in window.personal_summary.findChildren(QLabel)]
    assert any("seen 3 time(s)" in text for text in summary_labels)

    window.close()


def test_probe_bot_offline_faq(qapp: QApplication, settings) -> None:
    replies: list[str] = []
    worker = ProbeBotWorker(settings, history=[], prompt="how do I scan a domain?")
    worker.reply_ready.connect(replies.append)
    worker.start()
    assert worker.wait(8000)
    assert _wait(qapp, lambda: bool(replies))
    assert replies == [desktop.PROBE_BOT_FAQ]


def test_probe_bot_configured_calls_provider(qapp: QApplication, settings) -> None:
    settings.probe_bot_api_key = "test-key"
    settings.probe_bot_base_url = "https://api.test.local"
    settings.probe_bot_model = "test-model"
    seen: dict = {}

    def handler(request) -> object:
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.read().decode()
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "Hello from the provider!"}}]}
        )

    replies: list[str] = []
    worker = ProbeBotWorker(settings, history=[], prompt="hello")
    worker.reply_ready.connect(replies.append)
    with respx.mock(assert_all_called=False) as mock:
        mock.post("https://api.test.local/chat/completions").mock(side_effect=handler)
        worker.start()
        assert worker.wait(8000)
    assert _wait(qapp, lambda: bool(replies))
    assert replies == ["Hello from the provider!"]
    assert seen["auth"] == "Bearer test-key"
    assert '"model":"test-model"' in seen["body"]
    assert '"role":"user"' in seen["body"]


def test_probe_bot_page_flow(qapp: QApplication, settings) -> None:
    window = MainWindow(settings)
    window.bot_input.setText("how do I export a report?")
    window._on_bot_send()
    worker = window.bot_worker
    assert worker is not None
    assert worker.wait(8000)
    assert _wait(qapp, lambda: "No AI provider configured" in window.bot_display.toPlainText())
    assert window.bot_send_button.isEnabled()
    window.close()
