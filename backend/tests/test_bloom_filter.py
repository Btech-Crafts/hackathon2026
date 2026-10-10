"""Tests for scripts/build_bloom_filter.py (artifact pipeline correctness).

Covers: optimal sizing math, zero false negatives, header round-trip,
canonicalisation parity with ThreatStore, and bounded false positives.
All deterministic (fixed seeds) — no flakiness by construction.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import build_bloom_filter as bbf  # noqa: E402


def test_optimal_sizing_matches_3mb_story() -> None:
    """30L capacity @ 1% fp must land in the ~3.4 MB band."""
    m = bbf.optimal_m_bits(3_000_000, 0.01)
    assert 28_000_000 < m < 29_500_000
    assert bbf.optimal_k(m, 3_000_000) == 7
    assert m / 8 / 1024 / 1024 < 3.6


def test_no_false_negatives_and_round_trip() -> None:
    """Every inserted key probes positive, including after serialization."""
    bf = bbf.BloomFilter(bbf.optimal_m_bits(10_000, 0.01), 7)
    members = [f"vpa:user{i}@ybl" for i in range(500)] + ["phone:9876543210"]
    for key in members:
        bf.add(key)
    assert all(key in bf for key in members)
    restored = bbf.BloomFilter.from_bytes(bf.to_bytes(10_000, 0.01))
    assert all(key in restored for key in members)
    assert restored.count == 500 + 1


def test_known_cross_language_vectors() -> None:
    """First positions must equal the vectors quoted in VpaBloomFilter.kt."""
    m = 28_755_176
    assert bbf.BloomFilter._positions("vpa:refund-officer@ybl", m, 7)[:3] == [
        16995304,
        4933439,
        21626750,
    ]
    assert bbf.BloomFilter._positions("vpa:friend.123@okhdfcbank", m, 7)[:3] == [
        11359886,
        4482743,
        26360776,
    ]


def test_canonicalisation_parity() -> None:
    """VPA lower-casing and phone last-10 rules mirror ThreatStore."""
    assert bbf.canon_vpa("  Refund-Officer@YBL ") == "vpa:refund-officer@ybl"
    assert bbf.canon_phone("+91-9876543210") == "phone:9876543210"
    assert bbf.canon_phone("9876543210") == "phone:9876543210"


def test_false_positive_rate_bounded() -> None:
    """Small filter at ~80% load must stay well under a 5% measured FPR."""
    rng = random.Random(11)
    bf = bbf.BloomFilter(bbf.optimal_m_bits(5_000, 0.01), 7)
    for _ in range(4_000):
        bf.add(f"vpa:mule{rng.randrange(10**9):09d}@ybl")
    fp = sum(
        1
        for i in range(2_000)
        if f"vpa:clean{i:06d}@okhdfcbank" in bf
    )
    assert fp / 2_000 < 0.05


def test_shipped_artifact_loads_and_matches_threat_store() -> None:
    """The generated android asset must contain the mock-suspect VPAs."""
    blob = Path(__file__).resolve().parents[2] / "android" / "app" / "src" / "main" / "assets" / "threat_bloom.bin"
    assert blob.exists(), "run scripts/build_bloom_filter.py first"
    bf = bbf.BloomFilter.from_bytes(blob.read_bytes())
    assert "vpa:refund-officer@ybl" in bf
    assert "vpa:friend.123@okhdfcbank" not in bf
