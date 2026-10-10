"""Offline ETL: load flagged cybercrime identifiers into the threat store.

Supports CSV, JSON, and JSON-lines dumps of I4C / LEA-reported suspects.

Usage:
    python scripts/ingest_suspect_feed.py --input data/mock_suspects.csv --source i4c-mock
    python scripts/ingest_suspect_feed.py --input data/mock_suspects.json --source lea-dump
    python scripts/ingest_suspect_feed.py --input feed.jsonl --kind vpa --source i4c-feed

CSV format (header row required, case-insensitive):
    type_or_kind,value,source
    vpa,refund-officer@ybl,i4c-mock
    phone,+91-9876543210,i4c-mock
    handle,suspicious-handle,i4c-mock

JSON formats accepted:
    * List of objects:  [{"kind": "vpa", "value": "..."}, ...]
    * Dict with key:    {"suspects": [{"type": "vpa", "vpa": "..."}, ...]}
    * Bare VPA strings are auto-detected when they contain '@'.

All VPAs are normalised to lowercase; phones to last-10-digits.
Writes go to SQLite (durable) + Redis sets (fast) via ThreatStore.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterable

# Allow running as `python scripts/ingest_suspect_feed.py` from repo root
# as well as `python -m scripts.ingest_suspect_feed`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.threat_store import ThreatStore  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("ingest")

VALID_KINDS = {"vpa", "phone", "handle"}


def _infer_kind(value: str, default: str = "vpa") -> str:
    """Infer identifier kind when the feed omits an explicit type."""
    v = value.strip()
    if "@" in v:
        return "vpa"
    digits = "".join(c for c in v if c.isdigit())
    if len(digits) >= 10 and len(digits) - len(v.strip().lstrip("+")) <= 4:
        # Mostly-numeric string of phone length.
        if len(v) - len(digits) <= 4:
            return "phone"
    return default


def _normalise_record(raw: dict[str, Any], default_kind: str) -> tuple[str, str, str] | None:
    """Extract (kind, value, source) from a loose feed record."""
    kind = str(
        raw.get("kind") or raw.get("type") or raw.get("category") or default_kind
    ).lower()
    value = str(
        raw.get("value") or raw.get("vpa") or raw.get("upi_id") or raw.get("phone") or ""
    ).strip()
    source = str(raw.get("source") or raw.get("origin") or "i4c-feed").strip()
    if not value:
        return None
    if kind not in VALID_KINDS:
        kind = _infer_kind(value, default_kind)
    return kind, value, source or "i4c-feed"


def parse_csv(path: Path, default_kind: str) -> Iterable[tuple[str, str, str]]:
    """Yield (kind, value, source) tuples from a CSV dump."""
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        # Normalise headers to lowercase for tolerance.
        if reader.fieldnames:
            reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]
        for row in reader:
            lowered = {(k or "").strip().lower(): (v or "") for k, v in row.items()}
            rec = {
                "kind": lowered.get("kind") or lowered.get("type"),
                "value": lowered.get("value") or lowered.get("vpa") or lowered.get("upi_id"),
                "source": lowered.get("source"),
            }
            parsed = _normalise_record(rec, default_kind)
            if parsed:
                yield parsed


def parse_json(path: Path, default_kind: str) -> Iterable[tuple[str, str, str]]:
    """Yield (kind, value, source) tuples from JSON / JSONL dumps."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return
    records: list[Any] = []
    if path.suffix.lower() == ".jsonl" or "\n" in text and text.startswith("{"):
        for line in text.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    else:
        payload = json.loads(text)
        if isinstance(payload, dict) and "suspects" in payload:
            records = payload["suspects"]
        elif isinstance(payload, list):
            records = payload
        else:
            records = [payload]
    for item in records:
        if isinstance(item, str):
            if item.strip():
                yield _infer_kind(item, default_kind), item.strip(), "i4c-feed"
            continue
        if isinstance(item, dict):
            parsed = _normalise_record(item, default_kind)
            if parsed:
                yield parsed


def ingest(path: Path, source_override: str | None, default_kind: str, db_path: str | None) -> dict[str, int]:
    """Load a feed file into the threat store. Returns per-kind counters."""
    if not path.exists():
        raise FileNotFoundError(f"feed file not found: {path}")
    parser = parse_csv if path.suffix.lower() == ".csv" else parse_json
    store = ThreatStore(db_path) if db_path else ThreatStore()
    counts = {"vpa": 0, "phone": 0, "handle": 0, "skipped": 0}
    for kind, value, source in parser(path, default_kind):
        try:
            store.add_suspect(kind, value, source_override or source)  # type: ignore[arg-type]
            counts[kind] = counts.get(kind, 0) + 1
        except ValueError:
            counts["skipped"] += 1
    warmed = store.warm_redis_from_sqlite()
    logger.info("Redis warmed with %d keys", warmed)
    return counts


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    p = argparse.ArgumentParser(description="Ingest suspect UPI/phone feeds into threat store.")
    p.add_argument("--input", required=True, help="Path to CSV / JSON / JSONL feed file")
    p.add_argument("--source", default=None, help="Override source label for all records")
    p.add_argument("--kind", default="vpa", choices=sorted(VALID_KINDS), help="Default kind when feed omits type")
    p.add_argument("--db", default=None, help="Override SQLite path (defaults to backend/threat_intel.db)")
    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)
    counts = ingest(Path(args.input), args.source, args.kind, args.db)
    logger.info("Ingested %s -> %s", args.input, counts)
    print(json.dumps(counts, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
