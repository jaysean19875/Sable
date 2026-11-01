"""Capture desktop-app screenshots offscreen (dev-only, runs a real scan)."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.path.insert(0, os.getcwd())

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from projectosint.config import Settings
from projectosint.desktop import LicenseDialog, MainWindow, StartupNoticeDialog, _qss

OUT = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="osint-desktop-"))

app = QApplication([])
app.setStyle("Fusion")
app.setFont(QFont("Segoe UI", 9))
app.setStyleSheet(_qss())

settings = Settings(
    data_dir=TMP / "data",
    database=str(TMP / "data" / "osint.db"),
    deadline_s=10.0,
    source_timeout_s=8.0,
    log_json=False,
    rate_limit={"default_rps": 1.0, "burst": 2},
)

consent = LicenseDialog()
consent.key_input.setText("K8QEVB-7V2B54-DPQN9-9OCB1D6-ZVFASTH-MNBK42")
consent.show()
app.processEvents()
consent.grab().save(str(OUT / "desktop-license.png"))
consent.close()

notice = StartupNoticeDialog()
notice.show()
app.processEvents()
notice.grab().save(str(OUT / "desktop-notice.png"))
notice.close()

window = MainWindow(settings)
window.resize(1260, 840)
window.show()
app.processEvents()
window.grab().save(str(OUT / "desktop-idle.png"))

# Probe Bot page (offline FAQ mode, nothing sent anywhere)
window._nav_buttons["bot"].setChecked(True)
window._show_page("bot")
window.bot_input.setText("How do I export a report?")
window._on_bot_send()
if window.bot_worker is not None:
    window.bot_worker.wait(8000)
app.processEvents()
time.sleep(0.3)
app.processEvents()
window.grab().save(str(OUT / "desktop-probe-bot.png"))
window._nav_buttons["scan"].setChecked(True)
window._show_page("scan")

window.target_input.setText("example.com")
window._on_run_clicked()

deadline = time.monotonic() + 60
while window.report is None and time.monotonic() < deadline:
    app.processEvents()
    time.sleep(0.05)
app.processEvents()
window.grab().save(str(OUT / "desktop-results.png"))

if window.findings_table.rowCount():
    window.findings_table.selectRow(0)
    app.processEvents()
    window.grab().save(str(OUT / "desktop-provenance.png"))

window._nav_buttons["sources"].setChecked(True)
window._show_page("sources")
app.processEvents()
window.grab().save(str(OUT / "desktop-sources.png"))

window._show_page("history")
app.processEvents()
time.sleep(0.3)
app.processEvents()
window.grab().save(str(OUT / "desktop-history.png"))

# Personal Data page (idle, then a real check run)
window._nav_buttons["personal"].setChecked(True)
window._personal_popup_shown = True  # suppress the modal popup in headless capture
window._show_page("personal")
app.processEvents()
window.grab().save(str(OUT / "desktop-personal.png"))

window.personal_email_input.setText("nobody@example.com")
window.personal_username_input.setText("example")
window.personal_password_input.setText("password")
window._on_personal_run()
deadline = time.monotonic() + 90
while window.personal_report is None and time.monotonic() < deadline:
    app.processEvents()
    time.sleep(0.05)
app.processEvents()
window.grab().save(str(OUT / "desktop-personal-results.png"))

window.close()
print("captured:", sorted(p.name for p in OUT.glob("desktop-*.png")))
