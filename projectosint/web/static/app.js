/* ProjectOSINT dashboard — vanilla ES2020, no build step. */
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const STATUS_TEXT = {
  ok: "collected",
  cached: "cached",
  partial: "partial",
  timeout: "timeout",
  error: "error",
  skipped: "skipped",
};

const state = {
  report: null,
  sources: [],
  severities: new Set(SEVERITIES),
  query: "",
  source: "",
  scanId: null,
  openDetail: null,
};

/* ── utilities ───────────────────────────────────────────── */
function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function fmtMs(ms) {
  if (ms == null) return "—";
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
}

function fmtTime(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body && body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* non-JSON error body */ }
    throw new Error(detail);
  }
  return response.json();
}

function setHealth(ok, text) {
  $("#health-dot").classList.toggle("is-ok", ok);
  $("#health-dot").classList.toggle("is-err", !ok);
  $("#health-label").textContent = text;
}

/* ── navigation ──────────────────────────────────────────── */
const VIEW_TITLES = { scan: "New scan", history: "Scan history", sources: "Collector catalog" };

function showView(view) {
  $$(".nav-item").forEach((button) => button.classList.toggle("is-active", button.dataset.view === view));
  $$(".view").forEach((section) => section.classList.add("hidden"));
  $(`#view-${view}`).classList.remove("hidden");
  $("#view-title").textContent = VIEW_TITLES[view] || view;
  if (view === "history") loadHistory();
  if (view === "sources") renderSources();
}

/* ── scanning ────────────────────────────────────────────── */
let stream = null;

function resetScanUi() {
  $("#results").classList.add("hidden");
  $("#chips").innerHTML = "";
  $("#progress-count").textContent = "0 / 0";
  $("#form-error").classList.add("hidden");
}

function fail(message) {
  const box = $("#form-error");
  box.textContent = message;
  box.classList.remove("hidden");
  $("#run").disabled = false;
  $("#console").classList.add("hidden");
}

async function startScan(target) {
  resetScanUi();
  $("#empty").classList.add("hidden");
  $("#console").classList.remove("hidden");
  $("#run").disabled = true;
  try {
    const started = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, deadline_s: Number($("#deadline").value) }),
    });
    state.scanId = started.scan_id;
    follow(started.stream);
  } catch (error) {
    fail(error.message);
  }
}

function buildChips(names) {
  const container = $("#chips");
  container.innerHTML = "";
  names.forEach((name) => {
    const chip = document.createElement("span");
    chip.className = "chip is-running";
    chip.dataset.source = name;
    chip.innerHTML = `<span class="chip-dot"></span><span class="chip-name">${esc(name)}</span><span class="chip-count mono">…</span>`;
    container.appendChild(chip);
  });
  updateProgress(names.length, 0);
}

function updateProgress(total, done) {
  $("#progress-count").textContent = `${done} / ${total}`;
}

function follow(url) {
  if (stream) stream.close();
  let total = 0;
  let done = 0;

  stream = new EventSource(url);

  stream.addEventListener("scan_start", (event) => {
    const data = JSON.parse(event.data);
    total = data.sources.length;
    buildChips(data.sources);
  });

  stream.addEventListener("source_start", (event) => {
    const data = JSON.parse(event.data);
    const chip = $(`.chip[data-source="${CSS.escape(data.source)}"]`);
    if (chip) {
      chip.className = "chip is-running";
      chip.querySelector(".chip-count").textContent = "…";
    }
  });

  stream.addEventListener("source_done", (event) => {
    const data = JSON.parse(event.data);
    const chip = $(`.chip[data-source="${CSS.escape(data.source)}"]`);
    if (chip) {
      chip.className = `chip is-${data.status}`;
      chip.querySelector(".chip-count").textContent = data.count ?? 0;
      chip.title = data.error || data.note || data.status;
    }
    done += 1;
    updateProgress(total || done, done);
  });

  stream.addEventListener("scan_done", async () => {
    stream.close();
    $("#run").disabled = false;
    try {
      await loadReport(state.scanId);
    } catch (error) {
      fail(error.message);
    }
    refreshStats();
  });

  stream.addEventListener("job_error", (event) => {
    const data = JSON.parse(event.data);
    stream.close();
    fail(data.error || "scan failed");
  });

  stream.onerror = () => {
    if (stream) stream.close();
    $("#run").disabled = false;
  };
}

/* ── report rendering ────────────────────────────────────── */
async function loadReport(scanId) {
  const report = await api(`/api/scans/${scanId}`);
  state.report = report;
  state.scanId = report.scan_id || scanId;
  state.severities = new Set(SEVERITIES);
  state.query = "";
  state.source = "";
  $("#search").value = "";
  $("#console").classList.add("hidden");
  $("#empty").classList.add("hidden");
  $("#results").classList.remove("hidden");

  for (const fmt of ["json", "csv", "pdf"]) {
    $(`#export-${fmt}`).href = `/api/scans/${state.scanId}/export/${fmt}`;
  }
  renderSummary(report);
  renderSeverityFilters(report);
  renderSourceFilter(report);
  renderFindings();
}

function renderSummary(report) {
  const statuses = Object.entries(report.stats.by_status || {})
    .map(([key, value]) => `${STATUS_TEXT[key] || key} ${value}`)
    .join(" · ");
  const items = [
    ["target", esc(report.target.value)],
    ["findings", report.stats.total_findings],
    ["sources", `${report.stats.sources_total}`],
    ["duration", fmtMs(report.duration_ms)],
    ["http calls", report.stats.http_calls],
    ["status", statuses || "—"],
  ];
  $("#summary").innerHTML = items
    .map(([key, value]) => `<div class="summary-item"><span class="k">${esc(key)}</span><span class="v">${value}</span></div>`)
    .join("");
}

function renderSeverityFilters(report) {
  const counts = report.stats.by_severity || {};
  $("#sev-filters").innerHTML = SEVERITIES.map((sev) => {
    const on = state.severities.has(sev) ? " is-on" : "";
    return `<button type="button" class="sev-chip${on}" data-sev="${sev}">
      ${sev}<span class="n">${counts[sev] || 0}</span></button>`;
  }).join("");
}

function renderSourceFilter(report) {
  const names = (report.results || []).map((result) => result.source).sort();
  $("#source-filter").innerHTML = `<option value="">all sources</option>` +
    names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join("");
}

function severityRank(sev) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[sev] ?? 9;
}

function currentRows() {
  const report = state.report;
  if (!report) return [];
  const query = state.query.toLowerCase();
  return (report.findings || []).filter((finding) => {
    if (!state.severities.has(finding.severity)) return false;
    if (state.source && finding.source !== state.source) return false;
    if (!query) return true;
    return (
      finding.value.toLowerCase().includes(query) ||
      finding.kind.toLowerCase().includes(query) ||
      finding.source.toLowerCase().includes(query) ||
      (finding.detail || "").toLowerCase().includes(query)
    );
  }).sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.source.localeCompare(b.source));
}

function renderFindings() {
  const rows = currentRows();
  const body = $("#findings-body");
  $("#table-empty").classList.toggle("hidden", rows.length > 0);
  if (!rows.length) {
    body.innerHTML = "";
    return;
  }
  body.innerHTML = rows.slice(0, 800).map((finding, index) => {
    const open = state.openDetail === finding.id ? " is-open" : "";
    return `<tr class="row-main${open}" data-id="${esc(finding.id)}" data-index="${index}">
        <td><span class="sev sev-${esc(finding.severity)}">${esc(finding.severity)}</span></td>
        <td class="cell-src">${esc(finding.source)}</td>
        <td class="cell-kind">${esc(finding.kind)}</td>
        <td class="cell-value">${esc(finding.value)}</td>
        <td class="cell-detail">${esc(finding.detail || "")}</td>
      </tr>`;
  }).join("");
  if (rows.length > 800) {
    $("#table-empty").classList.remove("hidden");
    $("#table-empty").textContent = `Showing the first 800 of ${rows.length} matches — export to JSON/CSV for the full set.`;
  }
}

function detailRow(finding) {
  const p = finding.provenance || {};
  const tags = (finding.tags || []).join(", ") || "—";
  const evidence = finding.evidence && Object.keys(finding.evidence).length
    ? JSON.stringify(finding.evidence).slice(0, 900)
    : "—";
  return `<tr class="row-detail"><td colspan="5"><div class="detail-grid">
      <div><b>endpoint</b><span>${esc(p.endpoint || "—")}</span></div>
      <div><b>query</b><span>${esc(p.query || "—")}</span></div>
      <div><b>retrieved</b><span>${esc(fmtTime(p.retrieved_at))}</span></div>
      <div><b>confidence</b><span>${esc(finding.confidence)}</span></div>
      <div><b>tags</b><span>${esc(tags)}</span></div>
      <div><b>lawful scope</b><span>${esc(p.terms || "—")}</span></div>
      <div><b>evidence</b><span>${esc(evidence)}</span></div>
    </div></td></tr>`;
}

function toggleDetail(rowElement) {
  const id = rowElement.dataset.id;
  const existing = $(".row-detail");
  if (existing) existing.remove();
  if (state.openDetail === id) {
    state.openDetail = null;
    return;
  }
  const finding = (state.report.findings || []).find((item) => item.id === id);
  if (!finding) return;
  state.openDetail = id;
  rowElement.insertAdjacentHTML("afterend", detailRow(finding));
}

/* ── history & sources ───────────────────────────────────── */
async function loadHistory() {
  try {
    const data = await api("/api/scans?limit=40");
    const rows = data.scans || [];
    $("#history-empty").classList.toggle("hidden", rows.length > 0);
    $("#history-body").innerHTML = rows.map((scan) => `
      <tr class="is-clickable" data-scan="${esc(scan.scan_id)}">
        <td class="mono">${esc(scan.scan_id)}</td>
        <td class="cell-value">${esc(scan.target_value)}</td>
        <td class="cell-num">${scan.findings_total}</td>
        <td class="cell-num">${scan.sources_total}</td>
        <td>${esc(fmtTime(scan.started_at))}</td>
        <td class="cell-num">${fmtMs(scan.duration_ms)}</td>
      </tr>`).join("");
  } catch (error) {
    $("#history-empty").textContent = `Could not load history: ${error.message}`;
    $("#history-empty").classList.remove("hidden");
  }
}

function renderSources() {
  const rows = state.sources || [];
  const stateLabel = (source) => {
    if (!source.default_enabled) return "opt-in";
    return source.requires_key ? "key required" : "enabled";
  };
  $("#sources-body").innerHTML = rows.map((source) => `
    <tr>
      <td class="cell-src">${esc(source.name)}</td>
      <td>${esc(source.category)}</td>
      <td class="cell-kind">${esc((source.target_kinds || []).join(", "))}</td>
      <td>${esc(source.weight)}</td>
      <td class="cell-kind">${esc(source.requires_key || "—")}</td>
      <td>${esc(stateLabel(source))}</td>
    </tr>`).join("");
  $("#source-count").textContent = rows.length;
}

async function refreshStats() {
  try {
    const stats = await api("/api/stats");
    $("#stat-scans").textContent = stats.scans ?? "—";
    $("#stat-findings").textContent = stats.findings ?? "—";
  } catch { /* stats are cosmetic */ }
}

/* ── wiring ──────────────────────────────────────────────── */
function bind() {
  $$(".nav-item").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));

  $("#scan-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const target = $("#target").value.trim();
    if (!target) {
      fail("Enter a target first.");
      return;
    }
    startScan(target);
  });

  $("#sev-filters").addEventListener("click", (event) => {
    const chip = event.target.closest(".sev-chip");
    if (!chip) return;
    const sev = chip.dataset.sev;
    if (state.severities.has(sev)) state.severities.delete(sev);
    else state.severities.add(sev);
    chip.classList.toggle("is-on");
    renderFindings();
  });

  $("#search").addEventListener("input", (event) => {
    state.query = event.target.value;
    renderFindings();
  });

  $("#source-filter").addEventListener("change", (event) => {
    state.source = event.target.value;
    renderFindings();
  });

  $("#findings-body").addEventListener("click", (event) => {
    const row = event.target.closest("tr.row-main");
    if (row) toggleDetail(row);
  });

  $("#history-body").addEventListener("click", async (event) => {
    const row = event.target.closest("tr[data-scan]");
    if (!row) return;
    try {
      await loadReport(row.dataset.scan);
      showView("scan");
    } catch (error) {
      fail(error.message);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && document.activeElement !== $("#target") && document.activeElement !== $("#search")) {
      event.preventDefault();
      $("#search").focus();
    }
  });
}

async function boot() {
  bind();
  try {
    const health = await api("/api/health");
    setHealth(true, `${health.sources} sources · v${health.version}`);
  } catch {
    setHealth(false, "api unreachable");
  }
  try {
    const catalog = await api("/api/sources");
    state.sources = catalog.sources || [];
    renderSources();
  } catch { /* catalog is cosmetic until the API responds */ }
  refreshStats();
}

document.addEventListener("DOMContentLoaded", boot);
