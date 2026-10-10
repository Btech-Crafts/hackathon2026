"""Threat-intelligence store: Redis primary, SQLite fallback.

Design goals:
  * Instantaneous lookup (<10 ms) for known suspect VPAs / phones / handles.
  * Zero hard dependency on Redis — every read falls back to a local
    indexed SQLite database so the API never fails when Redis is down.
  * Canonical normalisation: VPAs lower-cased, phones reduced to last
    10 digits so ``+91-98...`` and ``98...`` match identically.

Redis layout (when available):
  * ``upi:suspects:vpa``    — SET of normalised VPAs
  * ``upi:suspects:phone``  — SET of normalised phones
  * ``upi:suspects:handle`` — SET of flagged raw handles

SQLite layout (always maintained):
  * ``suspects(kind TEXT, value TEXT, source TEXT, added_at TEXT)``
    with a unique index on ``(kind, value)``.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

logger = logging.getLogger(__name__)

SuspectKind = Literal["vpa", "phone", "handle"]

_NON_DIGIT_RE: re.Pattern[str] = re.compile(r"\D+")

_DEFAULT_DB_PATH = Path(
    os.environ.get(
        "THREAT_INTEL_DB",
        str(Path(__file__).resolve().parents[2] / "threat_intel.db"),
    )
)

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

_VPA_KEY = "upi:suspects:vpa"
_PHONE_KEY = "upi:suspects:phone"
_HANDLE_KEY = "upi:suspects:handle"


def normalize_vpa_value(vpa: str) -> str:
    """Lower-case and strip a VPA for canonical comparison."""
    return vpa.strip().lower()


def normalize_phone_value(phone: str) -> str:
    """Reduce a phone number to its last 10 digits (Indian numbering)."""
    digits = _NON_DIGIT_RE.sub("", phone.strip())
    # Keep country-code-tolerant form: last 10 digits for 10+ digit numbers.
    if len(digits) > 10:
        digits = digits[-10:]
    return digits


@dataclass
class ThreatHit:
    """Result of a threat-store lookup."""

    matched: bool
    kind: Optional[SuspectKind] = None
    value: Optional[str] = None
    source: Optional[str] = None


class ThreatStore:
    """Fast key-value threat lookup with Redis + SQLite fallback.

    All write paths update SQLite first (durable) then Redis (fast).
    All read paths try Redis first (sub-millisecond) then SQLite (<10 ms).
    """

    def __init__(self, db_path: Path | str = _DEFAULT_DB_PATH, redis_url: str = _REDIS_URL) -> None:
        self._db_path = Path(db_path)
        self._redis_url = redis_url
        self._lock = threading.Lock()
        self._redis: object | None = None
        self._init_sqlite()
        self._init_redis()

    # -- initialisation ----------------------------------------------------
    def _init_sqlite(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS suspects (
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'manual',
                    added_at TEXT NOT NULL,
                    PRIMARY KEY (kind, value)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_suspects_value ON suspects(value)")

    def _init_redis(self) -> None:
        try:
            import redis  # type: ignore[import-not-found]

            client = redis.Redis.from_url(
                self._redis_url, socket_connect_timeout=0.5, socket_timeout=0.5
            )
            client.ping()
            self._redis = client
            logger.info("ThreatStore: connected to Redis at %s", self._redis_url)
        except Exception as exc:  # Redis optional — fall back silently.
            logger.warning("ThreatStore: Redis unavailable (%s); using SQLite only.", exc)
            self._redis = None

    # -- writes -------------------------------------------------------------
    def add_suspect(self, kind: SuspectKind, raw_value: str, source: str = "i4c-feed") -> str:
        """Normalise and persist one suspect identifier. Returns stored value."""
        value = self._canonical(kind, raw_value)
        if not value:
            raise ValueError("empty suspect value after normalisation")
        added_at = datetime.now(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO suspects(kind, value, source, added_at) VALUES (?,?,?,?)",
                (kind, value, source, added_at),
            )
        self._redis_add(kind, value)
        return value

    def _redis_add(self, kind: SuspectKind, value: str) -> None:
        if self._redis is None:
            return
        try:
            key = {"vpa": _VPA_KEY, "phone": _PHONE_KEY, "handle": _HANDLE_KEY}[kind]
            self._redis.sadd(key, value)  # type: ignore[union-attr]
        except Exception as exc:
            logger.warning("ThreatStore: Redis write failed: %s", exc)

    @staticmethod
    def _canonical(kind: SuspectKind, raw: str) -> str:
        if kind == "vpa":
            return normalize_vpa_value(raw)
        if kind == "phone":
            return normalize_phone_value(raw)
        return raw.strip().lower()

    # -- reads --------------------------------------------------------------
    def _redis_contains(self, key: str, value: str) -> bool:
        if self._redis is None:
            return False
        try:
            return bool(self._redis.sismember(key, value))  # type: ignore[union-attr]
        except Exception:
            return False

    def _sqlite_lookup(self, kind: SuspectKind, value: str) -> Optional[str]:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT source FROM suspects WHERE kind = ? AND value = ? LIMIT 1",
                (kind, value),
            ).fetchone()
        return row[0] if row else None

    def lookup_vpa(self, vpa: str) -> ThreatHit:
        """Check a VPA against the suspect repository (<10 ms typical)."""
        value = normalize_vpa_value(vpa)
        if self._redis_contains(_VPA_KEY, value):
            return ThreatHit(True, "vpa", value, "redis")
        source = self._sqlite_lookup("vpa", value)
        if source is not None:
            return ThreatHit(True, "vpa", value, source)
        return ThreatHit(False)

    def lookup_phone(self, phone: str) -> ThreatHit:
        """Check a phone number against the suspect repository."""
        value = normalize_phone_value(phone)
        if not value:
            return ThreatHit(False)
        if self._redis_contains(_PHONE_KEY, value):
            return ThreatHit(True, "phone", value, "redis")
        source = self._sqlite_lookup("phone", value)
        if source is not None:
            return ThreatHit(True, "phone", value, source)
        return ThreatHit(False)

    def count(self) -> dict[str, int]:
        """Return suspect counts per kind (SQLite = source of truth)."""
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT kind, COUNT(*) FROM suspects GROUP BY kind"
            ).fetchall()
        return {kind: int(n) for kind, n in rows}

    def warm_redis_from_sqlite(self) -> int:
        """Re-populate Redis sets from SQLite. Returns number of keys loaded."""
        if self._redis is None:
            return 0
        total = 0
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute("SELECT kind, value FROM suspects").fetchall()
        pipe = self._redis.pipeline()  # type: ignore[union-attr]
        key_map = {"vpa": _VPA_KEY, "phone": _PHONE_KEY, "handle": _HANDLE_KEY}
        for kind, value in rows:
            pipe.sadd(key_map.get(kind, _VPA_KEY), value)
            total += 1
        pipe.execute()
        return total


_store_singleton: Optional[ThreatStore] = None
_store_lock = threading.Lock()


def get_threat_store() -> ThreatStore:
    """Process-wide singleton accessor (safe for FastAPI dependency use)."""
    global _store_singleton
    if _store_singleton is None:
        with _store_lock:
            if _store_singleton is None:
                _store_singleton = ThreatStore()
    return _store_singleton
