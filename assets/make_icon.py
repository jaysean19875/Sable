"""Generate assets/projectosint.ico from the app monogram (dev utility)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.path.insert(0, os.getcwd())

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QImage, QImageWriter, QPainter
from PySide6.QtWidgets import QApplication

OUT = Path(__file__).resolve().parent / "projectosint.ico"

app = QApplication([])
image = QImage(256, 256, QImage.Format.Format_ARGB32)
image.fill(Qt.GlobalColor.transparent)
painter = QPainter(image)
painter.setRenderHint(QPainter.RenderHint.Antialiasing)
painter.setBrush(QColor("#14171b"))
painter.setPen(QColor("#2f3641"))
painter.drawRoundedRect(QRect(8, 8, 240, 240), 46, 46)
painter.setPen(QColor("#a9bfd0"))
painter.setFont(QFont("Consolas", 96, QFont.Weight.Bold))
painter.drawText(image.rect(), Qt.AlignmentFlag.AlignCenter, "PO")
painter.end()

writer = QImageWriter(str(OUT), b"ico")
if writer.write(image):
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
else:
    print(f"ICO write failed: {writer.errorString()}", file=sys.stderr)
    raise SystemExit(1)
