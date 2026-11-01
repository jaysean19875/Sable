# ProjectOSINT

A bounded, provenance-rich OSINT collection platform: modular collectors, an
asyncio scheduler with hard deadlines, a normalised schema, a SQLite store, a
JSON/CSV/PDF export path and a native desktop UI â€” built so that every finding
can be traced back to the endpoint that produced it.

```text
 target â”€â”€â–¶ registry.select â”€â”€â–¶ asyncio.TaskGroup â”€â”€â–¶ normalise â”€â”€â–¶ SQLite â”€â”€â–¶ export
            (kind/category)      per-source timeout      dedupe       scans     JSON/CSV/PDF
                                 + global deadline        + caps     findings      â”‚
                                        â”‚                                        â–¼
                              token bucket per host                     desktop (PySide6)
                                        â”‚
                                 cache (target keyed)
```

## Download (Windows)

Prebuilt: <https://github.com/jaysean19875/Sable/releases/latest> â€” a single-file
`ProjectOSINT.exe`, no Python required. Drop it anywhere; it keeps its
`config.yaml`, `.env` and `data\` beside itself. Rebuild it any time with
`build_exe.ps1` (PyInstaller).

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,desktop]"

# desktop app (native window - the default experience)
.\.venv\Scripts\python.exe ProjectOSINT.py
#   - or -    .\.venv\Scripts\python.exe -m projectosint desktop

# CLI
.\.venv\Scripts\python.exe -m projectosint sources
.\.venv\Scripts\python.exe -m projectosint scan example.com --out out/
```

The desktop app is a single native window (PySide6): target input with a
deadline, a live console of per-collector status chips, a filterable findings
table with per-finding provenance, scan history, the collector catalog and a
one-time scope-and-consent notice.  No server, no browser, no port.

A scan writes `data/osint.db` (history), `data/cache.db` (result cache) and,
with `--out`, `report.json`, `findings.csv` and `report.pdf`.

## What a scan actually does

1. **Classify** the target (`domain`, `ip`, `url`, `email`, `username`) â€”
   routing is by target kind, so an IP-only adapter never runs against a
   domain.
2. **Select** collectors from the registry, honouring category/source filters
   and the disabled list.
3. **Run** them concurrently inside one `asyncio.TaskGroup`, each wrapped in
   its own timeout, inside a global `asyncio.timeout`. A source that hangs is
   cancelled and reported as `timeout`; the rest of the scan still returns.
4. **Normalise**: per-source de-duplication, a deterministic severity order,
   per-source caps, then persistence and export.
5. **Log** the scan, the source, the endpoint and the retrieval time. The JSON
   log (`data/logs/osint.jsonl`) is the audit trail.

Repeat scans of the same target are served from the cache (`status=cached`)
and finish in milliseconds without touching the network.

## Collectors

52 sources are registered; 51 are enabled by default. Five of those need an
API key and are reported as `skipped` â€” never as failures â€” when it is absent.
One search-engine source is deliberately opt-in.

| category | sources |
|---|---|
| dns | `dns_a`, `dns_aaaa`, `dns_ns`, `dns_mx`, `dns_txt`, `dns_caa`, `dns_soa`, `dns_spf`, `dns_dmarc`, `dns_dnssec` |
| certificates | `crtsh`, `tls_cert` |
| registration | `rdap_domain`, `rdap_ip`, `whois` |
| infrastructure | `ip_asn_cymru`, `ip_ptr`, `ip_geo` |
| web | `http_fingerprint`, `http_security_txt`, `http_robots`, `http_sitemap`, `wayback_cdx` |
| identity | `github_user`, `keybase_user`, `reddit_user`, `gravatar`, `email_domain`, `steam_user`, `gitlab_user`, `stackexchange_user`, `mastodon_user`, `wikipedia_user`, `chesscom_user`, `codeforces_user`, `devto_user`, `mojang_user`, `roblox_user`, `lichess_user`, `bitbucket_user`, `codeberg_user`, `bluesky_user`, `npm_user`, `speedrun_user`, `scratch_user`, `osrs_hiscores` |
| exposure / threat | `hibp_breaches`\*, `hibp_pastes`\*, `shodan_host`\*, `urlscan_search`\*, `virustotal_domain`\* |
| search | `search_ddg` (opt-in) |

\* requires a key. `python -m projectosint sources` prints the live catalog,
including which target kinds each adapter accepts.

## Personal Data

The desktop app's Personal Data tab checks one person's exposure: breach and
paste lookups for emails (HIBP, key gated), a password breach check and a
public-profile presence sweep. The sweep only uses keyless, public endpoints
that disclose leaked or public data: it never touches login walled or paid
platforms (that is why Discord and Microsoft account lookups are deliberately
absent). The sweep is capped at `personal_max_sources` (default **45**).

Privacy is the design, not a footnote:

- the password is hashed locally and only a **5 character SHA-1 prefix** is
  sent (HIBP k-anonymity, with response padding) â€” the password itself never
  leaves the machine and is never written to disk, logs or reports;
- nothing from this tab goes into the shared scan store or cache, so it is
  invisible in History and to other users of the same installation;
- reports are written to a `RESULTS` folder **next to the app** (for the
  frozen exe: `dist\RESULTS`) as JSON, CSV and plain text, and nothing is
  uploaded anywhere;
- the scope notice pops up **once per session** on first entry to the tab.

## License key and startup notice

On first launch the app asks for a **license key** and stores the activation
next to the app, so it is only asked once per install. Every launch shows a
short lawful-use notice (educational use only, no doxxing or harassment;
nothing is collected; results stay on your device in the `RESULTS` folder)
before the main window opens.

## Probe Bot

The Probe Bot tab is a small chat assistant for the app. Without a configured
key it answers from a built in guide and sends nothing anywhere. Point it at
any OpenAI-compatible chat API via `.env` (`OSINT_PROBE_BOT_API_KEY`,
`OSINT_PROBE_BOT_BASE_URL`, `OSINT_PROBE_BOT_MODEL`; DeepSeek defaults). With
a key configured, only your chat messages go to that provider.

### Scope and consent

Only public, unauthenticated endpoints are used. The platform does not bypass
authentication, does not fuzz paths, does not attempt zone transfers or login
form scraping, and honours `robots.txt` for anything beyond the homepage it is
explicitly asked to fingerprint. Every adapter carries a `lawful_note` that is
copied into the provenance of each finding and into every export. The desktop
app additionally asks for acknowledgement of this scope on first launch.

Rate limiting is not advisory: all HTTP traffic goes through a per-host token
bucket, and DNS lookups carry explicit timeouts.

## Configuration

`config.yaml` holds non-secret defaults; `.env` holds keys. Environment
variables (`OSINT_*`) override both, including nested keys via `__`:

```dotenv
OSINT_API_KEYS__SHODAN=...
OSINT_DEADLINE_S=15
OSINT_RATE_LIMIT__DEFAULT_RPS=0.5
```

Key settings:

| setting | default | meaning |
|---|---|---|
| `deadline_s` | 10 | global scan deadline |
| `source_timeout_s` | 8 | per-collector ceiling |
| `concurrency` | 12 | parallel collectors |
| `max_findings_per_source` | 200 | cap before normalisation |
| `cache_ttl_s` | 3600 | 0 disables the cache |
| `rate_limit.default_rps` | 1.0 | per-host token bucket |

## API (optional, library use only)

The web layer ships as library code for containers and automation; the CLI no
longer hosts it.  Start it explicitly when you want it:

```powershell
.\.venv\Scripts\python.exe -m uvicorn projectosint.web.app:app --port 8080
```

| method | path | purpose |
|---|---|---|
| `GET` | `/api/health` | liveness + collector count |
| `GET` | `/api/sources` | catalog with lawful notes |
| `POST` | `/api/scans` | start a scan, returns `{scan_id, stream}` (202) |
| `GET` | `/api/jobs/{id}/stream` | SSE: `scan_start`, `source_done`, `scan_done` |
| `GET` | `/api/scans` | stored + live scans |
| `GET` | `/api/scans/{id}` | full report |
| `GET` | `/api/scans/{id}/findings` | filtered findings |
| `GET` | `/api/scans/{id}/export/{json,csv,pdf}` | downloads |

## Development

```powershell
.\.venv\Scripts\python.exe -m pytest      # 138 tests, no network
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy projectosint
```

Tests run offline: HTTP adapters are exercised through `respx`, DNS through a
patched resolver, the scheduler through synthetic collectors that sleep, fail,
duplicate and time out on demand, and the desktop app on Qt's offscreen
platform with a synthetic engine.

## Layout

```text
ProjectOSINT.py    double-click launcher for the desktop app
build_exe.ps1      PyInstaller build for ProjectOSINT.exe
projectosint/
  config.py        typed settings, YAML + env precedence
  models.py        Target, Finding, Provenance, CollectorResult, ScanReport
  registry.py      CollectorSpec catalog + @register
  base.py          BaseCollector / CollectorContext
  http.py          shared AsyncClient, retries, Retry-After
  ratelimit.py     token buckets per host
  cache.py         SQLite result cache keyed by target
  scheduler.py     TaskGroup, per-source timeouts, global deadline
  pipeline.py      dedupe, caps, ordering
  store.py         scans + findings persistence
  export.py        JSON / CSV / PDF
  cli.py           scan | sources | stats | cache | desktop
  desktop.py       PySide6 window: chips console, findings, history, consent
  personal.py      Personal Data checks: HIBP layers, presence sweep, RESULTS
  collectors/      one module per source family
  web/             FastAPI app + static dashboard (library, not hosted)
tests/             138 offline tests
```

## Known limits

- The 10-second target assumes responsive sources; crt.sh and the Wayback CDX
  API routinely exceed it, which is exactly why they are `weight=heavy` and
  degrade to `partial` instead of blocking.
- WHOIS over port 43 is increasingly rate-limited by registries; RDAP is the
  primary path and WHOIS is the fallback that proves the point.
- The search-engine adapter is opt-in because automated querying may violate
  engine terms of service.
- PDF export caps the table at 400 rows; the JSON/CSV exports are complete.

