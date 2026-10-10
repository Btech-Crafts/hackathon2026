"""FastAPI server for the QR + UPI Scam Detection Engine.

Exposes:
  * ``GET  /health``                        — liveness probe.
  * ``GET  /api/v1/upi/threat-stats``       — threat-store counters.
  * ``POST /api/v1/upi/evaluate``           — high-throughput risk evaluation.
  * ``POST /api/v1/qr/decode-and-evaluate`` — QR image / URI risk evaluation.

Run locally:
  ``uvicorn app.main:app --reload --port 8000`` from ``backend/``.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import UpiEvaluateRequest, UpiEvaluateResponse
from app.services.heuristics import analyze_payment
from app.services.scorer import score_evaluation
from app.services.threat_store import get_threat_store
from app.routes.qr_routes import router as qr_router

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Warm the Redis cache from SQLite on startup (non-fatal on failure)."""
    try:
        store = get_threat_store()
        loaded = store.warm_redis_from_sqlite()
        logger.info("ThreatStore warmed: %d identifiers", loaded)
    except Exception as exc:  # pragma: no cover - startup resilience
        logger.warning("ThreatStore warm-up skipped: %s", exc)
    yield


app = FastAPI(
    title="QR + UPI Scam Detection Engine",
    version="1.0.0",
    description=(
        "Evaluates live UPI payment flows against scam heuristics and "
        "I4C/LEA threat intelligence. Returns a Unified 0-100 risk score."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Mobile clients + local dashboards; tighten in prod.
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(qr_router)


@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    """Liveness probe used by Docker / load-balancers."""
    return {"status": "ok", "service": "upi-scam-detection-engine"}


@app.get("/api/v1/upi/threat-stats", tags=["threat-intel"])
async def threat_stats() -> dict[str, object]:
    """Return suspect counts per identifier kind."""
    return {"counts": get_threat_store().count()}


@app.post("/api/v1/upi/evaluate", response_model=UpiEvaluateResponse, tags=["risk"])
async def evaluate_upi(payload: UpiEvaluateRequest) -> UpiEvaluateResponse:
    """Evaluate one observed payment flow and return a 0-100 risk verdict.

    Expected to sustain high throughput: heuristic analysis is pure-Python
    (microseconds) and the threat lookup is a Redis ``SISMEMBER`` with
    SQLite fallback (<10 ms).
    """
    started = time.perf_counter()

    vpa_normalized, findings = analyze_payment(
        vpa=payload.vpa,
        amount=payload.amount,
        payee_name=payload.payee_name,
        note=payload.note,
        mcc=payload.mcc,
        transaction_type=payload.transaction_type,
        user_expects_incoming=payload.user_expects_incoming,
    )

    hit = get_threat_store().lookup_vpa(vpa_normalized)

    score, level, action, flags, reasons, guidance = score_evaluation(
        findings=findings,
        is_known_suspect=hit.matched,
        suspect_source=hit.source,
    )

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    logger.info(
        "evaluate vpa=%s score=%d level=%s flags=%s ms=%.2f",
        vpa_normalized,
        score,
        level.value,
        flags,
        elapsed_ms,
    )

    return UpiEvaluateResponse(
        score=score,
        risk_level=level,
        recommended_action=action,
        is_known_suspect=hit.matched,
        vpa_normalized=vpa_normalized,
        flags=flags,
        reasons=reasons,
        guidance=guidance,
        evaluation_ms=round(elapsed_ms, 2),
    )
