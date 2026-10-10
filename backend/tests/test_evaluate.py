"""API-level tests for POST /api/v1/upi/evaluate."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services.threat_store import ThreatStore, get_threat_store  # noqa: E402

client = TestClient(app)


def _seed_suspect(vpa: str) -> None:
    store: ThreatStore = get_threat_store()
    try:
        store.add_suspect("vpa", vpa, "test-seed")
    except ValueError:
        pass


def test_health() -> None:
    """Liveness probe responds OK."""
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_benign_payment_is_low_risk() -> None:
    """Ordinary personal VPA with merchant code scores LOW."""
    r = client.post(
        "/api/v1/upi/evaluate",
        json={"vpa": "friend.123@okhdfcbank", "amount": 500, "mcc": "5411"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["score"] <= 29
    assert body["risk_level"] == "LOW"
    assert body["is_known_suspect"] is False
    assert 0 <= body["score"] <= 100


def test_impersonation_keyword_scores_high() -> None:
    """Authority keyword on personal handle without MCC must escalate."""
    r = client.post(
        "/api/v1/upi/evaluate",
        json={
            "vpa": "refund-officer@ybl",
            "amount": 15000,
            "payee_name": "RBI Refund Dept",
            "note": "customs fee to release refund",
            "transaction_type": "PAY",
            "user_expects_incoming": True,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["score"] >= 60
    assert body["risk_level"] in ("HIGH", "CRITICAL")
    assert "IMPERSONATION_KEYWORD" in body["flags"] or "REVERSE_COLLECT_SCAM" in body["flags"]
    assert len(body["reasons"]) > 0 and len(body["guidance"]) > 0


def test_reverse_collect_pattern() -> None:
    """Promised incoming funds + outgoing PAY = reverse-collect flag."""
    r = client.post(
        "/api/v1/upi/evaluate",
        json={
            "vpa": "buyer123@upi",
            "amount": 4999,
            "note": "accept to receive buyer payment",
            "transaction_type": "PAY",
            "user_expects_incoming": True,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "REVERSE_COLLECT_SCAM" in body["flags"]


def test_known_suspect_adds_80_and_blocks() -> None:
    """Threat-intel hit must dominate the score (>=80 => CRITICAL/BLOCK)."""
    _seed_suspect("scam-test-seed@ybl")
    r = client.post("/api/v1/upi/evaluate", json={"vpa": "SCAM-TEST-SEED@ybl"})
    assert r.status_code == 200
    body = r.json()
    assert body["is_known_suspect"] is True
    assert body["score"] >= 80
    assert body["risk_level"] == "CRITICAL"
    assert body["flags"][0] == "KNOWN_SUSPECT_VPA"


def test_invalid_vpa_and_untrusted_handle() -> None:
    """Malformed VPAs are flagged, not crashed on."""
    r = client.post("/api/v1/upi/evaluate", json={"vpa": "not-a-vpa"})
    assert r.status_code == 200
    assert "INVALID_VPA_SYNTAX" in r.json()["flags"]


def test_gibberish_vpa_is_unverifiable_not_clean() -> None:
    """A random, never-seen VPA must warn — never be declared safe."""
    r = client.post("/api/v1/upi/evaluate", json={"vpa": "jsfkjshfk124@oksbi"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "RANDOM_LOOKING_HANDLE" in body["flags"]
    assert body["score"] >= 30
    assert body["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert any("UNVERIFIED" in reason.upper() for reason in body["reasons"])


def test_normal_name_and_phone_vpas_not_flagged_random() -> None:
    """Realistic names and phone-number VPAs must not trip the gibberish rule."""
    for vpa in ("ramesh.kumar87@oksbi", "9876543210@ybl", "priya-sharma@okhdfcbank"):
        r = client.post("/api/v1/upi/evaluate", json={"vpa": vpa})
        assert r.status_code == 200, vpa
        assert "RANDOM_LOOKING_HANDLE" not in r.json()["flags"], vpa


def test_zero_signal_verdict_says_unverified() -> None:
    """An unknown-but-ordinary ID must be labelled unverified, never safe."""
    r = client.post("/api/v1/upi/evaluate", json={"vpa": "arun.menon42@okicici"})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_level"] == "LOW"
    assert any("UNVERIFIED" in reason.upper() for reason in body["reasons"]) or any(
        "UNVERIFIED" in flag for flag in body["flags"]
    ) or any("trust" in g.lower() for g in body["guidance"])

