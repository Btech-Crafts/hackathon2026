"""Pytest suite for POST /api/v1/qr/decode-and-evaluate.

Covers the four mandated scenarios plus parser/validator unit checks and
the image-upload path (QR PNG generated in-memory with ``qrcode``):

1. Legitimate merchant QR      — verified MCC + INR → LOW / SAFE_TO_PROCEED.
2. Disguised URL QR            — http short-link → HIGH+ / DO_NOT_SCAN_OR_PAY.
3. Reverse-collect cashback QR — deceptive ``tn`` + RECEIVE context → 95+ CRITICAL.
4. P2P utility impersonation   — corporate ``pn`` on consumer handle, no MCC → HIGH+.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services.qr_analyzer import (  # noqa: E402
    MerchantValidator,
    ReverseCollectDetector,
    evaluate_qr_payload,
    parse_upi_payload,
)

client = TestClient(app)

LEGIT_MERCHANT_QR = (
    "upi://pay?pa=swiggy.orders@okhdfcbank&pn=Swiggy%20Pvt%20Ltd"
    "&mc=5812&am=499.00&cu=INR&tr=ORDER12345&tn=Food%20order"
)

CASHBACK_LURE_QR = (
    "upi://pay?pa=cashback-offer99@ybl&pn=Cashback%20Dept"
    "&am=4999&cu=INR&tn=Cashback%20credit%20claim%20bonus%20receive%20refund"
)

UTILITY_SPOOF_QR = (
    "upi://pay?pa=electricity-bill-help@okhdfcbank&pn=Electricity%20Dept%20Support"
    "&am=2500&cu=INR&tn=Electricity%20bill%20payment"
)

SHORT_LINK_QR = "https://bit.ly/upi-pay-verify-99x"


# ---------------------------------------------------------------------------
# 1. Legitimate merchant QR
# ---------------------------------------------------------------------------


def test_legitimate_merchant_qr_is_low_risk() -> None:
    """Verified MCC + INR merchant intent must stay LOW / safe."""
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": LEGIT_MERCHANT_QR, "expected_action": "PAY"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mcc_status"] == "VERIFIED_MERCHANT"
    assert body["is_reverse_collect_scam"] is False
    assert body["risk_score"] < 30
    assert body["severity"] == "LOW"
    assert body["guidance"] == "SAFE_TO_PROCEED"
    assert body["vpa"] == "swiggy.orders@okhdfcbank"


# ---------------------------------------------------------------------------
# 2. Disguised URL QR
# ---------------------------------------------------------------------------


def test_disguised_short_link_qr_flagged() -> None:
    """HTTP short-link QR must be flagged as redirect/phishing vector."""
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": SHORT_LINK_QR, "expected_action": "PAY"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "URL_REDIRECT_VECTOR" in body["risk_factors"]
    assert "SHORT_LINK_OBFUSCATION" in body["risk_factors"]
    assert body["risk_score"] >= 60
    assert body["severity"] in ("HIGH", "CRITICAL")
    assert body["guidance"] in ("DO_NOT_PAY_VERIFY_FIRST", "DO_NOT_SCAN_OR_PAY")


def test_plain_url_qr_flagged_without_short_link() -> None:
    """Non-short-link URLs are still redirect vectors (lower but elevated)."""
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": "https://payments-example.com/settle?id=99", "expected_action": "PAY"},
    )
    assert r.status_code == 200
    assert "URL_REDIRECT_VECTOR" in r.json()["risk_factors"]


# ---------------------------------------------------------------------------
# 3. Reverse-collect cashback QR
# ---------------------------------------------------------------------------


def test_reverse_collect_cashback_qr_is_critical() -> None:
    """Deceptive tn + RECEIVE context on upi://pay must hit 95+ CRITICAL."""
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": CASHBACK_LURE_QR, "expected_action": "RECEIVE"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_reverse_collect_scam"] is True
    assert body["risk_score"] >= 95
    assert body["severity"] == "CRITICAL"
    assert body["guidance"] == "DO_NOT_SCAN_OR_PAY"
    assert any(
        f in body["risk_factors"]
        for f in ("REVERSE_COLLECT_CONTEXT_MISMATCH", "REVERSE_COLLECT_TN_LURE")
    )


def test_reverse_collect_detector_unit_rules() -> None:
    """Detector unit: mismatch floors at 95; tn lure alone still scams."""
    det = ReverseCollectDetector()
    intent = parse_upi_payload(CASHBACK_LURE_QR)
    is_scam, _w, flags, _r = det.evaluate(intent, "RECEIVE")
    assert is_scam and "REVERSE_COLLECT_CONTEXT_MISMATCH" in flags

    verdict = evaluate_qr_payload(CASHBACK_LURE_QR, expected_action="RECEIVE")
    assert verdict.is_reverse_collect_scam and verdict.risk_score >= 95

    # Same QR without RECEIVE context: tn lure still fires, score lower.
    verdict_pay = evaluate_qr_payload(CASHBACK_LURE_QR, expected_action="PAY")
    assert verdict_pay.is_reverse_collect_scam is True
    assert "REVERSE_COLLECT_TN_LURE" in verdict_pay.risk_factors


# ---------------------------------------------------------------------------
# 4. P2P utility impersonation
# ---------------------------------------------------------------------------


def test_p2p_utility_impersonation_flagged_high() -> None:
    """Corporate pn on a consumer handle with no MCC → P2M spoof, HIGH+."""
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": UTILITY_SPOOF_QR, "expected_action": "PAY"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "P2M_SPOOF_SUSPECT" in body["risk_factors"]
    assert body["mcc_status"] == "P2M_SPOOF_SUSPECT"
    assert body["risk_score"] >= 60
    assert body["severity"] in ("HIGH", "CRITICAL")


def test_merchant_validator_unit() -> None:
    """Validator unit: bad MCC, non-INR, and verified paths."""
    mv = MerchantValidator()
    ok_intent = parse_upi_payload(LEGIT_MERCHANT_QR)
    status, _w, _f, _r = mv.audit(ok_intent)
    assert status == "VERIFIED_MERCHANT"

    bad_mcc = parse_upi_payload("upi://pay?pa=a@upi&pn=Shop&mc=AB12&cu=INR")
    assert mv.audit(bad_mcc)[0] == "INVALID_MCC_FORMAT"

    foreign = parse_upi_payload("upi://pay?pa=a@upi&pn=Shop&mc=5411&cu=USD")
    assert mv.audit(foreign)[0] == "NON_INR_CURRENCY"


# ---------------------------------------------------------------------------
# Parser + image-upload path
# ---------------------------------------------------------------------------


def test_npcI_parser_handles_mandate_and_bare_vpa() -> None:
    """Mandate scheme, bare VPA stickers, and garbage classify correctly."""
    assert parse_upi_payload("upi://mandate?pa=x@ybl&pn=N&am=100&cu=INR").kind == "mandate"
    assert parse_upi_payload("shopkeeper@okhdfcbank").kind == "pay"
    assert parse_upi_payload("not a qr at all !!!").kind == "unknown"


def test_image_upload_decodes_and_evaluates() -> None:
    """Multipart image upload → server-side decode → same verdict as payload."""
    try:
        import qrcode  # type: ignore[import-not-found]
    except ImportError:
        import pytest

        pytest.skip("qrcode not installed")
    img = qrcode.make(LEGIT_MERCHANT_QR)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        files={"image": ("qr.png", buf.getvalue(), "image/png")},
        data={"expected_action": "PAY"},
    )
    # OpenCV/pyzbar may be absent in minimal CI — accept either a clean LOW
    # verdict or an explicit 422 (no decoder available), never a 500.
    assert r.status_code in (200, 422), r.text
    if r.status_code == 200:
        body = r.json()
        assert body["decoded_from"] == "image"
        assert body["vpa"] == "swiggy.orders@okhdfcbank"


def test_missing_payload_and_image_returns_422() -> None:
    """Empty submissions are rejected with a clear error."""
    r = client.post("/api/v1/qr/decode-and-evaluate", json={"payload": ""})
    assert r.status_code == 422
