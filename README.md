# QR + UPI Scam Detection Engine (Feature 4)

AI-powered cybercrime prevention: checks UPI IDs and QR codes against
scam heuristics + flagged repositories, and warns before money moves.

> **Runs fully on-device.** Since the server cutover, the Android app needs
> no backend, no account, no same-network setup: `RiskEngine.kt` ports the
> entire Python pipeline (heuristics, reverse-collect, mandate-hijack,
> merchant/MCC audit, tamper guard, scorer) to pure Kotlin with identical
> rule codes, weights and 95-floors. The Python backend remains in
> `backend/` for server-side/bulk use and its 37-test suite guards parity.

```
android/   Kotlin client — AccessibilityService + overlay alert + QR scanner
backend/   Python FastAPI risk engine (POST /api/v1/upi/evaluate, POST /api/v1/qr/decode-and-evaluate)
scripts/   Threat-feed ingestion ETL (CSV / JSON / JSONL -> Redis + SQLite)
data/      Mock I4C/LEA suspect dumps for local testing
```

## 1. Backend setup (local, ~3 min)

**Prereqs:** Python 3.11+, pip. Redis optional (falls back to SQLite automatically).

```powershell
cd upi-scam-detection-engine\backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Load mock suspect records (works with or without Redis running):
python ..\scripts\ingest_suspect_feed.py --input ..\data\mock_suspects.csv --source i4c-mock
# Expected: {"vpa": 6, "phone": 2, "handle": 1, "skipped": 0}

# Start the API:
uvicorn app.main:app --reload --port 8000
```

Verify:

```powershell
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/v1/upi/evaluate `
  -H "Content-Type: application/json" `
  -d '{"vpa":"refund-officer@ybl","amount":25000,"payee_name":"RBI Refund Dept","note":"pay customs fee to receive refund","transaction_type":"PAY","user_expects_incoming":true}'
# -> {"score":100,"risk_level":"CRITICAL","recommended_action":"BLOCK","is_known_suspect":true,...}
```

Interactive docs: http://localhost:8000/docs

**With Redis (recommended for <1 ms lookups):**

```powershell
# Option A — Docker:
docker run -d -p 6379:6379 redis:7-alpine
# Option B — repo compose, if present: docker compose up -d redis
$env:REDIS_URL = "redis://localhost:6379/0"
uvicorn app.main:app --reload --port 8000
```

Set a custom SQLite path with `$env:THREAT_INTEL_DB = "D:\intel\threat.db"`.

**Run tests:**

```powershell
cd upi-scam-detection-engine
python -m pytest backend/tests -v
# 16 passed: 6 UPI-flow tests + 10 QR/NPCI tests
```

## 2. Risk-engine contract

### 2a. UPI flow evaluation

`POST /api/v1/upi/evaluate`

Request:

```json
{
  "vpa": "refund-officer@ybl",
  "amount": 15000,
  "payee_name": "RBI Refund Dept",
  "note": "customs fee to release refund",
  "mcc": null,
  "app_package": "com.phonepe.app",
  "transaction_type": "PAY",
  "user_expects_incoming": true
}
```

Response (Unified 0–100 format):

```json
{
  "score": 100,
  "risk_level": "CRITICAL",
  "recommended_action": "BLOCK",
  "is_known_suspect": true,
  "vpa_normalized": "refund-officer@ybl",
  "flags": ["KNOWN_SUSPECT_VPA", "IMPERSONATION_KEYWORD", "REVERSE_COLLECT_SCAM"],
  "reasons": ["This payee ID is flagged in the cybercrime threat repository ..."],
  "guidance": ["Do NOT pay this ID. Report it ... call 1930 (India)."],
  "evaluation_ms": 2.01
}
```

| Score | Level | Client action |
|-------|-------|---------------|
| 0–29 | LOW | ALLOW |
| 30–59 | MEDIUM | WARN (passive banner) |
| 60–79 | HIGH | WARN_BLOCK (overlay, encourage cancel) |
| 80–100 | CRITICAL | BLOCK (full-screen overlay, urge report) |

Scoring weights: known-suspect **+80**, reverse-collect **+35**,
impersonation keyword **+30**, invalid syntax **+25**, typosquat **+25**,
untrusted handle **+15**, missing MCC **+12**, pressure language **+10**,
high amount **+10** — clamped to 100.

### 2b. QR decode-and-evaluate

`POST /api/v1/qr/decode-and-evaluate` — accepts **JSON** or **multipart**:

```powershell
# JSON with raw URI payload:
curl -X POST http://localhost:8000/api/v1/qr/decode-and-evaluate `
  -H "Content-Type: application/json" `
  -d '{"payload":"upi://pay?pa=cashback-offer99@ybl&pn=Cashback Dept&am=4999&cu=INR&tn=Cashback credit claim bonus","expected_action":"RECEIVE"}'
# -> {"risk_score":100,"severity":"CRITICAL","is_reverse_collect_scam":true,"guidance":"DO_NOT_SCAN_OR_PAY",...}

# Multipart with gallery screenshot (server-side pyzbar/OpenCV decode):
curl -X POST http://localhost:8000/api/v1/qr/decode-and-evaluate `
  -F "image=@qr-screenshot.png" -F "expected_action=PAY"
```

Response contract:

```json
{
  "vpa": "cashback-offer99@ybl",
  "payee_name": "Cashback Dept",
  "amount": "4999",
  "is_reverse_collect_scam": true,
  "mcc_status": "P2M_SPOOF_SUSPECT",
  "risk_score": 100,
  "severity": "CRITICAL",
  "risk_factors": ["REVERSE_COLLECT_CONTEXT_MISMATCH", "REVERSE_COLLECT_TN_LURE"],
  "guidance": "DO_NOT_SCAN_OR_PAY"
}
```

Detection layers (`backend/app/services/qr_analyzer.py`):
- **NPCI parser** (`parse_upi_payload`): safe `urllib.parse` extraction of
  `pa/pn/mc/am/tr/cu/tn`; classifies `pay` / `mandate` / `url` / `unknown`.
  HTTP(S) payloads → `URL_REDIRECT_VECTOR` (+45); known short-links
  (`bit.ly`, `tinyurl`, …) → `SHORT_LINK_OBFUSCATION` (+20).
- **ReverseCollectDetector**: `RECEIVE` context + `upi://pay` → floor **95**;
  deceptive `tn` phrases (`receive refund`, `cashback credit`, `lottery prize`,
  `reward release`, `claim bonus`, …) + debit URI → `REVERSE_COLLECT_TN_LURE` (+40);
  hardcoded `am` → +10; `mandate` disguised as credit → flagged.
- **MerchantValidator**: `cu != INR` → `NON_INR_CURRENCY` (+30); bad `mc` →
  `INVALID_MCC_FORMAT` (+20); corporate-claim `pn` (electricity/utility/support/…)
  with no MCC → `P2M_SPOOF_SUSPECT` (+35); valid `mc` → `VERIFIED_MERCHANT`.
  PSP-handle substrings are excluded from name matching; phone-like locals
  (`\d{10,}`) on consumer handles stay spoof-suspect even with an MCC.

QR verdicts are enriched with the VPA heuristic engine + threat-store hits
(known suspect +80) before clamping to 0–100.

### 2c. Edge-case guards (mandate hijack + tamper + value anomaly)

`POST /api/v1/qr/decode-and-evaluate` runs two extra stages on every payload
(verified by `backend/tests/test_edge_cases.py`, 12 tests):

- **AutoPay mandate inspector** (`app/services/mandate_analyzer.py`):
  parses `upi://mandate?...` (`validitystart/validityend/recurrence/am/share`,
  `DDMMYYYY` + ISO dates). Recurring auto-debit (`recurrence` present **or**
  window > 30 days) to an MCC-less payee → `RECURRING_MANDATE_HIJACK`,
  score floor **95** (`is_mandate_hijack: true`). Recurring *with* a valid MCC
  (e.g. OTT biller) → informational only, not a hijack.
  ```powershell
  curl -X POST http://localhost:8000/api/v1/qr/decode-and-evaluate `
    -H "Content-Type: application/json" `
    -d '{"payload":"upi://mandate?pa=victim99@ybl&pn=Support Desk&am=5000&cu=INR&recurrence=monthly&validitystart=01012026&validityend=01012027"}'
  # -> {"risk_score":95+,"severity":"CRITICAL","is_mandate_hijack":true,...}
  ```
- **Value-anomaly & tamper guard** (`app/services/anomaly_detector.py`):
  duplicated critical params (`pa`/`am`/`mc`/… via order-preserving `parse_qsl`)
  → `DUPLICATE_PARAM_<TAG>` (+35, parser-differential attack); zero-width chars
  (`U+200B/C/D`, `U+FEFF`) in `pa` → `ZERO_WIDTH_VPA_TRICK` (+30); non-ASCII /
  malformed VPA → obfuscation flags (+20); non-ISO `cu` → `CURRENCY_TAMPER` (+30);
  ≥ ₹25,000 to an MCC-less consumer handle (`@ybl/@ibl/@upi/@paytm/…`) →
  `HIGH_VALUE_UNVERIFIED_P2P` (+25).

## 3. Threat-feed ingestion

```powershell
python scripts/ingest_suspect_feed.py --input data/mock_suspects.csv --source i4c-mock
python scripts/ingest_suspect_feed.py --input data/mock_suspects.json --source lea-dump
python scripts/ingest_suspect_feed.py --input feed.jsonl --kind vpa --source i4c-feed --db backend/threat_intel.db
```

- VPAs lower-cased, phones reduced to last 10 digits before storage.
- Writes go to SQLite (durable, indexed) **and** Redis sets
  (`upi:suspects:vpa|phone|handle`) for sub-millisecond `SISMEMBER` lookups.
- Without Redis the API serves from SQLite in <10 ms; no code change needed.

## 4. Android setup

Files:

```
android/app/src/main/java/com/cybercrime/paymentguard/
  MainActivity.kt                   # launcher: Check-UPI-ID screen + pop-up self-tests
  OverlayAlertService.kt            # floating HIGH/CRITICAL warning + MEDIUM banner
  QRScannerActivity.kt              # CameraX + ML Kit scanner + gallery picker
  QRImageDecoder.kt                 # gallery-bitmap decode + payload pre-classifier
  OfflineThreatCache.kt             # on-device <5 ms threat interception
  VpaBloomFilter.kt                 # 3 MB national-scale Bloom reader
android/AndroidManifest.snippet.xml     # merge into your manifest
android/build.gradle.snippet.kts        # coroutines + CameraX + ML Kit deps
```

> Scope note: passive UPI-app inspection via AccessibilityService
> (`PaymentGuardAccessibilityService`) was removed — the app verifies only
> manually entered UPI IDs and scanned QR codes. No accessibility permission
> is needed anymore.

**Manifest permissions** (see `AndroidManifest.snippet.xml`):

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<activity android:name=".QRScannerActivity" ... />
```

**Steps:**

1. Merge the snippet into `app/src/main/AndroidManifest.xml`; copy the `.kt`
   files into place (backend URL lives in `MainActivity.BACKEND_URL` and
   `QRScannerActivity.QR_ENDPOINT` — emulator → `http://10.0.2.2:8000/...`,
   physical device → `http://<your-lan-ip>:8000/...`).
2. Build & install, then grant **Display over other apps** when prompted
   (for the warning pop-ups). No accessibility permission is required.
3. Verify with the in-app self-tests: **"Test: full danger pop-up"**,
   **"Test: small caution banner"**, then **"Check this UPI ID"**
   (`refund-officer@ybl` → CRITICAL + pop-up; `friend.123@okhdfcbank` →
   LOW; `jsfkjshfk124@oksbi` → MEDIUM + banner + UNVERIFIED wording).

Privacy: only on-screen VPA/amount/name text is processed; no keystrokes,
no PIN/OTP capture; overlay never clicks inside the payment app.
QR scanner transmits only the decoded *string* — never raw images.

**QR scanner usage:** launch `QRScannerActivity`, toggle `I expect: PAY/RECEIVE`
to set the reverse-collect context, then scan live or pick a gallery image.
Short-link/URL QRs get an instant local banner; every payload is POSTed to
`/api/v1/qr/decode-and-evaluate`, and HIGH/CRITICAL verdicts raise the overlay.

**Offline interception** (`OfflineThreatCache.kt` + `VpaBloomFilter.kt`): lock-free
in-memory lookup (bundled scam VPAs + 3 MB national-scale Bloom filter, plus a
SharedPreferences-persisted server snapshot via `updateFromServer()` for
background syncs) consulted **first** on every ID check / QR decode — strictly
<5 ms, no I/O, works in flight mode. `MainActivity` shows the verdict instantly
and raises the overlay on HIGH/CRITICAL; `QRScannerActivity` shows an instant
banner and still confirms with the backend. Normalisation mirrors the
server (`lowercase + trim`; hosts lower-cased).

## 5. Project layout
```
upi-scam-detection-engine/
  README.md
  android/...            # Kotlin client
  backend/
    app/main.py          # FastAPI + CORS + lifespan warm-up (+ QR router)
    app/schemas.py       # Pydantic request/response (Unified 0-100 + QR verdict)
    app/services/heuristics.py    # 6-rule engine
    app/services/threat_store.py  # Redis primary, SQLite fallback
    app/services/scorer.py        # weights -> score/level/action
    app/services/qr_analyzer.py   # NPCI parser + ReverseCollectDetector + MerchantValidator
    app/services/mandate_analyzer.py  # upi://mandate parser + hijack engine (floor 95)
    app/services/anomaly_detector.py  # duplicate-param / obfuscation / high-value P2P guard
    app/routes/qr_routes.py       # POST /api/v1/qr/decode-and-evaluate
    requirements.txt
    tests/test_evaluate.py
    tests/test_qr_evaluate.py     # 10 QR/NPCI tests (4 mandated scenarios)
  scripts/ingest_suspect_feed.py
  data/mock_suspects.{csv,json}
```

## 6. Production notes

- Tighten `allow_origins` in `main.py` from `*` to your domains.
- Put the API behind HTTPS + auth (API key / mTLS from the app).
- Refresh threat intel on a schedule: cron the ingest script against the
  I4C feed, then `warm_redis_from_sqlite()`.
- On-device, move `BACKEND_URL` to `BuildConfig` flavours (dev/staging/prod).

## 7. Release build (shipped in `android-app/`)

The app is fully on-device: no server, no INTERNET permission, no
accessibility monitoring — only Check-UPI-ID + QR Scanner + overlay pop-ups.

- **Artifacts:** `app/build/outputs/apk/release/app-release.apk` (direct
  distribution) and `app/build/outputs/bundle/release/app-release.aab`
  (Play Store upload). v1.0.0 (versionCode 1), minSdk 26, signed with
  `keystore/release.keystore` (alias `paymentguard`, 30-year validity).
- **Keystore warning:** back up `android-app/keystore/release.keystore` +
  the passwords in `local.properties` somewhere safe (password manager +
  offline copy). Losing the keystore means you can NEVER ship an update
  under the same Play Store listing again.
- **Before release:** fill `TrustedStore.ORG_TRUSTED_VPAS` with your
  organization's official VPAs (lowercase) so your own IDs verify green
  instead of UNVERIFIED; bump `versionCode`/`versionName` per release.
- **Trust model:** exact-match allowlist — bundled org IDs + per-device
  "Trust this ID" entries (SharedPreferences, never leave the phone).
  Trusted IDs short-circuit to verified-LOW on both screens.
- **Play Store notes:** no INTERNET permission and no data collection make
  the Data Safety form trivial; declare Display-over-other-apps +
  Camera usage; the AAB is what Play Console wants for new apps.
