"""ProjectOSINT - bounded, provenance-rich OSINT collection.

The package is deliberately layered so that every piece can be exercised
without the network:

    config   -> typed settings (YAML + env/.env)
    models   -> Pydantic schema: Target, Finding, CollectorResult, ScanReport
    registry -> declarative catalog + decorator based collector registration
    base     -> BaseCollector contract every adapter implements
    http     -> shared AsyncClient, retries, per-host token buckets
    cache    -> SQLite result cache keyed by target (repeat scans are instant)
    store    -> SQLite persistence of scans and findings
    scheduler-> bounded-concurrency orchestration with deadlines
    pipeline -> normalisation and de-duplication
"""

__version__ = "0.1.0"
APP_NAME = "ProjectOSINT"

# Importing the package populates the collector registry, so every entry point
# (CLI, API, tests) sees the same catalog without bespoke wiring.
from . import collectors as collectors  # noqa: E402

__all__ = ["APP_NAME", "__version__", "collectors"]
