"""QR decode-and-evaluate route.

Endpoint:
    POST /api/v1/qr/decode-and-evaluate

Accepts **both** calling conventions so mobile and web clients stay simple:

1. JSON: ``{"payload": "upi://pay?pa=...&...", "expected_action": "RECEIVE"}``
2. Multipart: ``payload`` / ``expected_action`` form fields plus an optional
   ``image`` file (PNG/JPEG/WebP screenshot or camera capture).

Image bytes are decoded with :func:`decode_qr_image_bytes` (pyzbar first,
OpenCV fallback). The first decoded string (or the explicit ``payload`` when
both are supplied — explicit wins) is evaluated by
:func:`evaluate_qr_payload`, enriched with VPA heuristics and threat-intel.
"""

from __future__ import annotations

import time
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.schemas import QrEvaluateResponse
from app.services.heuristics import analyze_payment
from app.services.qr_analyzer import (
    decode_qr_image_bytes,
    evaluate_qr_payload,
    parse_amount,
    parse_upi_payload,
)
from app.services.threat_store import get_threat_store

router = APIRouter(prefix="/api/v1/qr", tags=["qr"])

ExpectedAction = Literal["RECEIVE", "PAY"]


def _normalise_expected(value: object) -> ExpectedAction:
    """Coerce a loose expected_action value to RECEIVE/PAY (default PAY)."""
    if isinstance(value, str) and value.strip().upper() == "RECEIVE":
        return "RECEIVE"
    return "PAY"


async def _evaluate_one(
    raw_payload: str,
    expected_action: ExpectedAction,
    decoded_from: Literal["payload", "image"],
) -> QrEvaluateResponse:
    """Run the full QR pipeline for a single decoded string."""
    started = time.perf_counter()
    intent = parse_upi_payload(raw_payload)

    # Upstream VPA heuristics (impersonation / typosquat / pressure language)
    # enrich the QR verdict when a payee VPA is present.
    extra_weight = 0
    extra_flags: list[str] = []
    extra_reasons: list[str] = []
    known_suspect = False
    suspect_source: Optional[str] = None
    if intent.pa:
        try:
            _norm, findings = analyze_payment(
                vpa=intent.pa,
                amount=parse_amount(intent.am),
                payee_name=intent.pn,
                note=intent.tn,
                mcc=intent.mc if intent.mc and intent.mc.isdigit() else None,
                transaction_type="PAY",
                user_expects_incoming=(expected_action == "RECEIVE"),
            )
            extra_weight = sum(f.weight for f in findings)
            # Avoid double-counting signals the QR engine already emits with
            # QR-specific codes; keep heuristic-only codes for context.
            qr_owned = {
                "REVERSE_COLLECT_SCAM",
                "SUSPICIOUS_CREDIT_LURE",
                "MISSING_MCC",
                "IMPERSONATION_KEYWORD",
                "IMPERSONATION_KEYWORD_UNVERIFIED",
            }
            for f in findings:
                if f.code not in qr_owned:
                    extra_flags.append(f"VPA_{f.code}")
                    extra_reasons.append(f.reason)
        except Exception:
            pass
        hit = get_threat_store().lookup_vpa(intent.pa)
        known_suspect = hit.matched
        suspect_source = hit.source

    verdict = evaluate_qr_payload(
        raw_payload,
        expected_action=expected_action,
        known_suspect=known_suspect,
        suspect_source=suspect_source,
        extra_heuristics_weight=extra_weight,
        extra_flags=extra_flags,
        extra_reasons=extra_reasons,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return QrEvaluateResponse(
        vpa=verdict.vpa,
        payee_name=verdict.payee_name,
        amount=verdict.amount,
        is_reverse_collect_scam=verdict.is_reverse_collect_scam,
        mcc_status=verdict.mcc_status,
        risk_score=verdict.risk_score,
        severity=verdict.severity,
        risk_factors=verdict.risk_factors,
        guidance=verdict.guidance,
        reasons=verdict.reasons,
        is_known_suspect=known_suspect,
        is_mandate_hijack=verdict.is_mandate_hijack,
        decoded_from=decoded_from,
        evaluation_ms=round(elapsed_ms, 2),
    )


@router.post("/decode-and-evaluate", response_model=QrEvaluateResponse)
async def decode_and_evaluate(request: Request) -> QrEvaluateResponse:
    """Decode (optional image) and evaluate a QR payload.

    Returns 422 when neither a payload nor a decodable image is supplied.
    """
    content_type = request.headers.get("content-type", "")

    # --- JSON convention ----------------------------------------------------
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Invalid JSON body: {exc}") from exc
        payload = (body.get("payload") or "").strip() if isinstance(body, dict) else ""
        expected = _normalise_expected(body.get("expected_action") if isinstance(body, dict) else None)
        if not payload:
            raise HTTPException(status_code=422, detail="Provide 'payload' or upload 'image'.")
        return await _evaluate_one(payload, expected, "payload")

    # --- Multipart convention -------------------------------------------------
    form = await request.form()
    payload = str(form.get("payload") or "").strip()
    expected = _normalise_expected(form.get("expected_action"))
    image = form.get("image")

    image_bytes: bytes = b""
    if image is not None and hasattr(image, "read"):
        try:
            image_bytes = await image.read()  # type: ignore[union-attr]
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Could not read image: {exc}") from exc
        if len(image_bytes) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Image exceeds 10 MB limit.")

    if payload:
        return await _evaluate_one(payload, expected, "payload")

    if image_bytes:
        decoded = decode_qr_image_bytes(image_bytes)
        if not decoded:
            raise HTTPException(
                status_code=422,
                detail="No QR code found in image (or image libraries unavailable).",
            )
        return await _evaluate_one(decoded[0], expected, "image")

    raise HTTPException(status_code=422, detail="Provide 'payload' or upload 'image'.")


# Backwards-compatible alias without trailing path differences.
@router.post("/decode_and_evaluate", response_model=QrEvaluateResponse, include_in_schema=False)
async def decode_and_evaluate_alias(request: Request) -> JSONResponse:
    """Underscore alias for the canonical hyphenated route."""
    resp = await decode_and_evaluate(request)
    return JSONResponse(content=resp.model_dump())
