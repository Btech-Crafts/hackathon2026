"""Edge-case protection tests: mandate hijacks, tampering, value anomalies.

Verifies the three mandated scenarios plus unit-level guards:

1. Legitimate single payment vs. disguised recurring mandate.
2. Duplicate-parameter (parser-differential) attacks.
3. High-value (>= Rs 25,000) unverified-P2P anomaly scoring.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services.anomaly_detector import (  # noqa: E402
    audit_qr_anomalies,
    find_duplicate_params,
)
from app.services.mandate_analyzer import classify_mandate, evaluate_mandate  # noqa: E402

client = TestClient(app)

LEGIT_SINGLE_PAY = (
    "upi://pay?pa=swiggy.orders@okhdfcbank&pn=Swiggy%20Pvt%20Ltd"
    "&mc=5812&am=499.00&cu=INR&tn=Food%20order"
)

# Disguised mandate: monthly auto-debit for a year, MCC-less "support" payee.
HIJACK_MANDATE = (
    "upi://mandate?pa=victim99@ybl&pn=Support%20Desk"
    "&am=5000&cu=INR&tn=Verification"
    "&recurrence=monthly&validitystart=01012026&validityend=01012027"
)

# Registered biller mandate: monthly OTT sub, valid MCC, 90-day window.
REGISTERED_MANDATE = (
    "upi://mandate?pa=netflix.billing@okhdfcbank&pn=Netflix%20Pvt%20Ltd"
    "&mc=5812&am=649&cu=INR&tn=Subscription"
    "&recurrence=monthly&validitystart=01012026&validityend=01042026"
)

DUPE_PA_QR = (
    "upi://pay?pa=friendly-shop@upi&pa=mule-wallet@paytm"
    "&pn=Local%20Store&am=1200&cu=INR&tn=Groceries"
)

HIGH_VALUE_P2P_QR = (
    "upi://pay?pa=deal-broker99@ybl&pn=Rajesh"
    "&am=45000&cu=INR&tn=Land%20advance"
)

ZERO_WIDTH_QR = (
    "upi://pay?pa=refund\u200bofficer@ybl&pn=Refund%20Dept&am=5000&cu=INR&tn=Refund"
)


# ---------------------------------------------------------------------------
# 1. Legitimate single payment vs. disguised recurring mandate
# ---------------------------------------------------------------------------


def test_legit_single_pay_is_not_mandate_hijack() -> None:
    """One-time pay intents never trigger mandate-hijack logic."""
    is_hijack, weight, flags, _reasons, intent = evaluate_mandate(LEGIT_SINGLE_PAY)
    assert intent.is_mandate is False
    assert is_hijack is False and weight == 0 and flags == []
    assert classify_mandate(LEGIT_SINGLE_PAY) == "NOT_MANDATE"

    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": LEGIT_SINGLE_PAY, "expected_action": "PAY"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_mandate_hijack"] is False
    assert body["severity"] == "LOW"


def test_disguised_recurring_mandate_hits_95_critical() -> None:
    """Monthly MCC-less mandate spanning a year must score 95+ CRITICAL."""
    is_hijack, _w, flags, _r, intent = evaluate_mandate(HIJACK_MANDATE)
    assert intent.is_mandate is True
    assert intent.has_recurrence is True
    assert intent.validity_days == 365
    assert is_hijack is True
    assert "RECURRING_MANDATE_HIJACK" in flags
    assert classify_mandate(HIJACK_MANDATE) == "HIJACK"

    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": HIJACK_MANDATE, "expected_action": "PAY"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_mandate_hijack"] is True
    assert "RECURRING_MANDATE_HIJACK" in body["risk_factors"]
    assert body["risk_score"] >= 95
    assert body["severity"] == "CRITICAL"
    assert body["guidance"] == "DO_NOT_SCAN_OR_PAY"


def test_long_window_without_recurrence_tag_still_hijack() -> None:
    """validityend > 30 days alone implies a long-lived auto-debit."""
    uri = (
        "upi://mandate?pa=ghost@ybl&pn=Helper&am=2000&cu=INR"
        "&validitystart=01012026&validityend=15032026"
    )
    is_hijack, _, flags, _, intent = evaluate_mandate(uri)
    assert intent.validity_days == 73
    assert is_hijack is True
    assert "RECURRING_MANDATE_HIJACK" in flags


def test_registered_mandate_is_not_hijack() -> None:
    """Recurring mandate WITH a valid MCC is a normal biller flow."""
    is_hijack, _, flags, _, _ = evaluate_mandate(REGISTERED_MANDATE)
    assert is_hijack is False
    assert "MCC_MANDATE_REGISTERED" in flags
    assert classify_mandate(REGISTERED_MANDATE) == "RECURRING_REGISTERED"


# ---------------------------------------------------------------------------
# 2. Duplicate-parameter attacks
# ---------------------------------------------------------------------------


def test_duplicate_pa_detected_at_unit_level() -> None:
    """parse_qsl-based scan surfaces both `pa` values."""
    dupes = find_duplicate_params(DUPE_PA_QR)
    assert set(dupes["pa"]) == {"friendly-shop@upi", "mule-wallet@paytm"}


def test_duplicate_param_qr_flagged_by_api() -> None:
    """Duplicated critical tags elevate the QR verdict with explicit flags."""
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": DUPE_PA_QR, "expected_action": "PAY"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "DUPLICATE_PARAM_PA" in body["risk_factors"]
    assert body["risk_score"] >= 30
    assert any("repeats critical parameter" in reason for reason in body["reasons"])


def test_duplicate_amount_flagged() -> None:
    """`am` duplication (preview Rs 10 vs debit Rs 50,000) is also caught."""
    uri = "upi://pay?pa=shop@upi&pn=Shop&am=10&am=50000&cu=INR"
    dupes = find_duplicate_params(uri)
    assert dupes["am"] == ["10", "50000"]
    _w, flags, _r = audit_qr_anomalies(uri, "shop@upi", 10.0, None, "INR")
    assert "DUPLICATE_PARAM_AM" in flags


# ---------------------------------------------------------------------------
# 3. High-value anomaly scoring
# ---------------------------------------------------------------------------


def test_high_value_p2p_flagged() -> None:
    """Rs 45,000 to an MCC-less @ybl handle must raise HIGH_VALUE flag."""
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": HIGH_VALUE_P2P_QR, "expected_action": "PAY"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "HIGH_VALUE_UNVERIFIED_P2P" in body["risk_factors"]
    assert body["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_high_value_with_mcc_is_not_p2p_anomaly() -> None:
    """Same amount WITH an MCC is a normal large merchant payment."""
    _w, flags, _r = audit_qr_anomalies(
        "upi://pay?pa=dealer@okhdfcbank&am=45000&mc=5411&cu=INR",
        "dealer@okhdfcbank",
        45000.0,
        "5411",
        "INR",
    )
    assert "HIGH_VALUE_UNVERIFIED_P2P" not in flags


def test_sub_threshold_p2p_not_flagged() -> None:
    """Rs 500 to a friend stays quiet on the value-anomaly channel."""
    _w, flags, _r = audit_qr_anomalies(
        "upi://pay?pa=friend@upi&am=500&cu=INR", "friend@upi", 500.0, None, "INR"
    )
    assert "HIGH_VALUE_UNVERIFIED_P2P" not in flags


# ---------------------------------------------------------------------------
# Obfuscation extras (zero-width / currency tamper)
# ---------------------------------------------------------------------------


def test_zero_width_vpa_trick_flagged() -> None:
    """Invisible characters in `pa` trigger the evasion flag."""
    r = client.post(
        "/api/v1/qr/decode-and-evaluate",
        json={"payload": ZERO_WIDTH_QR, "expected_action": "PAY"},
    )
    assert r.status_code == 200, r.text
    assert "ZERO_WIDTH_VPA_TRICK" in r.json()["risk_factors"]


def test_currency_symbol_tamper_flagged() -> None:
    """`cu` carrying a currency symbol instead of ISO code is tamper."""
    _w, flags, _r = audit_qr_anomalies(
        "upi://pay?pa=a@upi&am=100&cu=INR", "shop@upi", 100.0, None, "Rs."
    )
    assert "CURRENCY_TAMPER" in flags
