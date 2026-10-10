"""Pydantic schemas for the UPI Scam Detection Engine API.

Conforms to the Unified Risk Engine format: a 0-100 integer score,
a categorical risk level, explainable reasons, and actionable guidance.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    """Standardised risk buckets used by all risk engines."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendedAction(str, Enum):
    """Intervention the mobile client should take."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    WARN_BLOCK = "WARN_BLOCK"
    BLOCK = "BLOCK"


class UpiEvaluateRequest(BaseModel):
    """Incoming payment-flow observation from the Android client.

    Attributes:
        vpa: Payee Virtual Payment Address, e.g. ``refund-officer@ybl``.
        amount: Transaction amount in INR. ``None`` if not yet visible.
        payee_name: Display name scraped from the payment screen.
        note: UPI transaction note / remark scraped from the screen.
        mcc: Merchant Category Code if exposed by the app (4-digit string).
        app_package: Android package name where the flow was observed.
        transaction_type: ``PAY`` (outgoing debit, default) or ``COLLECT``
            (incoming collect request shown to the user).
        user_expects_incoming: True when the user believes they are
            *receiving* money (refund / prize / buyer payment). Used to
            detect reverse-collect scams where a debit is disguised as credit.
        device_id: Opaque hashed device identifier for rate-limiting/logging.
    """

    vpa: str = Field(..., min_length=3, max_length=320, description="Payee VPA / UPI ID")
    amount: Optional[float] = Field(default=None, ge=0, description="Amount in INR")
    payee_name: Optional[str] = Field(default=None, max_length=200)
    note: Optional[str] = Field(default=None, max_length=500)
    mcc: Optional[str] = Field(default=None, description="4-digit Merchant Category Code")
    app_package: Optional[str] = Field(default=None, max_length=200)
    transaction_type: Literal["PAY", "COLLECT"] = Field(default="PAY")
    user_expects_incoming: bool = Field(default=False)
    device_id: Optional[str] = Field(default=None, max_length=128)

    @field_validator("vpa")
    @classmethod
    def _strip_vpa(cls, v: str) -> str:
        return v.strip()

    @field_validator("mcc")
    @classmethod
    def _validate_mcc(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        v = v.strip()
        if not (v.isdigit() and len(v) == 4):
            raise ValueError("mcc must be a 4-digit string")
        return v


class UpiEvaluateResponse(BaseModel):
    """Standardised Unified Risk Engine output (0-100)."""

    score: int = Field(..., ge=0, le=100, description="Normalised risk score")
    risk_level: RiskLevel
    recommended_action: RecommendedAction
    is_known_suspect: bool = Field(..., description="Hit in I4C/LEA threat intel store")
    vpa_normalized: str = Field(..., description="Lower-cased canonical VPA")
    flags: list[str] = Field(default_factory=list, description="Machine-readable finding codes")
    reasons: list[str] = Field(
        default_factory=list, description="Human-readable 'Why am I at risk?'"
    )
    guidance: list[str] = Field(
        default_factory=list, description="Human-readable 'What should I do?'"
    )
    evaluation_ms: float = Field(..., description="Server-side evaluation latency in ms")


class QrEvaluateJsonRequest(BaseModel):
    """JSON alternative to the multipart QR endpoint (no image)."""

    payload: str = Field(..., min_length=1, max_length=4000, description="Decoded QR text")
    expected_action: Literal["RECEIVE", "PAY"] = Field(default="PAY")


class QrEvaluateResponse(BaseModel):
    """Structured QR verdict — superset of the required contract."""

    vpa: str = Field(default="", description="Extracted payee VPA (pa tag)")
    payee_name: str = Field(default="", description="Extracted payee name (pn tag)")
    amount: Optional[str] = Field(default=None, description="Raw am tag as encoded")
    is_reverse_collect_scam: bool
    mcc_status: str = Field(description="e.g. VERIFIED_MERCHANT / UNVERIFIED_INDIVIDUAL")
    risk_score: int = Field(..., ge=0, le=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_factors: list[str]
    guidance: str = Field(description="Machine-readable client action")
    reasons: list[str] = Field(default_factory=list)
    is_known_suspect: bool = False
    is_mandate_hijack: bool = Field(
        default=False, description="True when a recurring mandate targets an MCC-less payee"
    )
    decoded_from: Literal["payload", "image"] = "payload"
    evaluation_ms: float = 0.0
