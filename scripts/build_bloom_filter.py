"""Build the on-device Bloom-filter threat artifact (~3 MB for ~30L IDs).

Reads suspect identifiers from the local threat store (SQLite, populated via
``ingest_suspect_feed.py``) and/or CSV feeds, and writes a compact,
versioned Bloom filter that the Android app memory-maps for <1 ms offline
lookups. Stdlib only — no third-party dependencies.

Sizing (standard Bloom math, m = -n*ln(p) / (ln2)^2 bits):
    n = 3,000,000 (I4C registry scale, ~30.48L identifiers per MHA Jun-2026),
    p = 0.01  -->  m ~= 28.76M bits ~= 3.43 MB, k = 7 hashes.

The file size depends on *capacity*, not on how many identifiers are loaded
today, so the artifact is national-registry-sized from day one and grows
only via versioned rebuilds/deltas — never per-record.

Hashing contract (MUST match ``VpaBloomFilter.kt`` exactly):
    key      = "<kind>:<canonical value>" encoded UTF-8
               (kind = "vpa" | "phone"; vpa lower-cased+stripped,
                phone reduced to last 10 digits — same as ThreatStore)
    digest1  = SHA256("UPIBF:v1:" + key)
    digest2  = SHA256(key + ":UPIBF:v1")
    h1       = u64be(digest1[0:8])
    h2       = u64be(digest2[0:8]) forced odd (h2 | 1)
    positions[i] = (h1 + i * h2) % m_bits,  i = 0..k-1

File layout (all integers little-endian):
    magic[8] = b"UPIBF1\\0\\0", m_bits:u64, k:u32, capacity:u64, count:u64,
    fp_rate:f64, bits[m_bits rounded up to bytes]

Usage:
    python scripts/build_bloom_filter.py --db backend/threat_intel.db
    python scripts/build_bloom_filter.py --csv data/mock_suspects.csv --out android/app/src/main/assets/threat_bloom.bin
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import random
import sqlite3
import struct
import sys
from pathlib import Path

MAGIC = b"UPIBF1\x00\x00"
HEADER_FMT = "<8sQIQ Qd"  # magic, m_bits, k, capacity, count, fp_rate
HEADER_SIZE = struct.calcsize(HEADER_FMT)

DEFAULT_CAPACITY = 3_000_000
DEFAULT_FP_RATE = 0.01


def optimal_m_bits(n: int, p: float) -> int:
    """Return the optimal bit-array size for n items at fp-rate p."""
    return math.ceil(-n * math.log(p) / (math.log(2) ** 2))


def optimal_k(m_bits: int, n: int) -> int:
    """Return the optimal hash count for m bits and n items."""
    return max(1, round((m_bits / n) * math.log(2)))


class BloomFilter:
    """Minimal Bloom filter with a frozen cross-language hashing contract."""

    def __init__(self, m_bits: int, k: int) -> None:
        """Args: m_bits: bit-array length; k: number of hash positions."""
        self.m_bits = m_bits
        self.k = k
        self.count = 0
        self.bits = bytearray((m_bits + 7) // 8)

    @staticmethod
    def _positions(key: str, m_bits: int, k: int) -> list[int]:
        raw = key.encode("utf-8")
        h1 = int.from_bytes(hashlib.sha256(b"UPIBF:v1:" + raw).digest()[0:8], "big")
        h2 = int.from_bytes(hashlib.sha256(raw + b":UPIBF:v1").digest()[0:8], "big") | 1
        return [(h1 + i * h2) % m_bits for i in range(k)]

    def add(self, key: str) -> None:
        """Insert one canonical ``"<kind>:<value>"`` key."""
        for pos in self._positions(key, self.m_bits, self.k):
            self.bits[pos // 8] |= 1 << (pos % 8)
        self.count += 1

    def __contains__(self, key: str) -> bool:
        """Membership probe. No false negatives; ~p false positives at capacity."""
        return all(
            self.bits[pos // 8] & (1 << (pos % 8))
            for pos in self._positions(key, self.m_bits, self.k)
        )

    def to_bytes(self, capacity: int, fp_rate: float) -> bytes:
        """Serialize with header."""
        header = struct.pack(
            HEADER_FMT, MAGIC, self.m_bits, self.k, capacity, self.count, fp_rate
        )
        return header + bytes(self.bits)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BloomFilter":
        """Deserialize; raises ValueError on bad magic/version."""
        magic, m_bits, k, _capacity, count, _fp = struct.unpack(
            HEADER_FMT, data[:HEADER_SIZE]
        )
        if magic != MAGIC:
            raise ValueError("not a UPIBF threat-filter file")
        obj = cls(m_bits, k)
        obj.bits = bytearray(data[HEADER_SIZE : HEADER_SIZE + (m_bits + 7) // 8])
        obj.count = count
        return obj


# ---------------------------------------------------------------------------
# Key canonicalisation (mirrors ThreatStore + OfflineThreatCache.normalizeVpa)
# ---------------------------------------------------------------------------


def canon_vpa(vpa: str) -> str:
    """Return the ``vpa:<lower>`` Bloom key for a raw VPA."""
    return "vpa:" + vpa.strip().lower()


def canon_phone(phone: str) -> str:
    """Return the ``phone:<last10>`` Bloom key for a raw phone number."""
    digits = "".join(c for c in phone.strip() if c.isdigit())
    if len(digits) > 10:
        digits = digits[-10:]
    return "phone:" + digits


def load_keys_from_db(db_path: Path) -> list[str]:
    """Load ``kind:value`` keys from the threat-intel SQLite store."""
    if not db_path.exists():
        return []
    keys: list[str] = []
    with sqlite3.connect(db_path) as conn:
        try:
            rows = conn.execute("SELECT kind, value FROM suspects").fetchall()
        except sqlite3.OperationalError:
            return []
    for kind, value in rows:
        if kind == "vpa":
            keys.append(canon_vpa(str(value)))
        elif kind == "phone":
            keys.append(canon_phone(str(value)))
        elif kind == "handle":
            keys.append("handle:" + str(value).strip().lower())
    return keys


def load_keys_from_csv(csv_path: Path) -> list[str]:
    """Load keys from an ingest-format CSV (kind/value/source columns)."""
    keys: list[str] = []
    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        fnames = [(h or "").strip().lower() for h in (reader.fieldnames or [])]
        for row in reader:
            rec = {fnames[i]: (v or "") for i, v in enumerate(list(row.values()))}
            kind = (rec.get("kind") or rec.get("type") or "vpa").strip().lower()
            value = (rec.get("value") or rec.get("vpa") or "").strip()
            if not value:
                continue
            if kind == "phone":
                keys.append(canon_phone(value))
            elif kind == "handle":
                keys.append("handle:" + value.lower())
            else:
                keys.append(canon_vpa(value))
    return keys


def measured_fpr(bf: BloomFilter, trials: int = 20_000, seed: int = 7) -> float:
    """Estimate the false-positive rate with random non-member VPAs."""
    rng = random.Random(seed)
    fp = 0
    for _ in range(trials):
        probe = f"clean{rng.randrange(10**12):012d}@cleanhandle{rng.randrange(10**6):06d}"
        if ("vpa:" + probe) in bf:
            fp += 1
    return fp / trials


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    p = argparse.ArgumentParser(description="Build the on-device Bloom threat artifact.")
    p.add_argument("--db", default="backend/threat_intel.db", help="Threat SQLite path")
    p.add_argument("--csv", default=None, help="Extra ingest-format CSV feed")
    p.add_argument("--capacity", type=int, default=DEFAULT_CAPACITY)
    p.add_argument("--fp", type=float, default=DEFAULT_FP_RATE, help="Target fp-rate")
    p.add_argument(
        "--out",
        default="android/app/src/main/assets/threat_bloom.bin",
        help="Output artifact path",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]

    keys: list[str] = []
    keys += load_keys_from_db(Path(args.db if Path(args.db).is_absolute() else repo_root / args.db))
    if args.csv:
        keys += load_keys_from_csv(
            Path(args.csv if Path(args.csv).is_absolute() else repo_root / args.csv)
        )
    # De-duplicate while preserving order.
    keys = list(dict.fromkeys(keys))

    m_bits = optimal_m_bits(args.capacity, args.fp)
    k = optimal_k(m_bits, args.capacity)
    bf = BloomFilter(m_bits, k)
    for key in keys:
        bf.add(key)

    out = Path(args.out if Path(args.out).is_absolute() else repo_root / args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    blob = bf.to_bytes(args.capacity, args.fp)
    out.write_bytes(blob)

    # Self-verification: zero false negatives + FPR sanity + round-trip.
    assert all(key in bf for key in keys), "false negative detected — hashing bug"
    rt = BloomFilter.from_bytes(blob)
    assert all(key in rt for key in keys), "round-trip failure"
    fpr = measured_fpr(bf)

    size_mb = len(blob) / (1024 * 1024)
    print(f"capacity : {args.capacity:,}  target_fp : {args.fp}")
    print(f"m_bits   : {m_bits:,}  k={k}  inserted={len(keys):,}")
    print(f"artifact : {out}  ({size_mb:.2f} MB)")
    print(f"measured FPR on 20k clean probes (near-empty filter): {fpr:.5f}")
    print(f"theoretical FPR at full capacity: ~{args.fp}")
    print("verification vectors (key -> first 3 positions):")
    for demo in ["vpa:refund-officer@ybl", "vpa:friend.123@okhdfcbank"]:
        print(f"  {demo} -> {BloomFilter._positions(demo, m_bits, k)[:3]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
