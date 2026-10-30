"""Capture dashboard screenshots for visual verification (dev-only)."""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent
BASE = "http://127.0.0.1:8099"

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1460, "height": 960}, device_scale_factor=2)
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(700)
    page.screenshot(path=str(OUT / "01-idle.png"))

    page.fill("#target", "example.com")
    page.click("#run")
    page.wait_for_selector("#results:not(.hidden)", timeout=60_000)
    page.wait_for_timeout(900)
    page.screenshot(path=str(OUT / "02-results.png"))

    # open one finding's provenance drawer
    rows = page.locator("#findings-body tr.row-main")
    if rows.count():
        rows.nth(3).click()
        page.wait_for_timeout(350)
        page.screenshot(path=str(OUT / "03-provenance.png"))

    page.click('.nav-item[data-view="sources"]')
    page.wait_for_timeout(600)
    page.screenshot(path=str(OUT / "04-sources.png"))

    page.click('.nav-item[data-view="history"]')
    page.wait_for_timeout(700)
    page.screenshot(path=str(OUT / "05-history.png"))

    console_errors = []
    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
    page.click('.nav-item[data-view="scan"]')
    page.wait_for_timeout(300)
    browser.close()

print("captured:", sorted(p.name for p in OUT.glob("*.png")))
