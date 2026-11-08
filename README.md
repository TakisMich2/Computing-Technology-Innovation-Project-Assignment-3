# PhishCheck

PhishCheck is a phishing URL checker developed for COS30049 Computing
Technology Innovation Project. Enter a web address and it gives you a
trust score from 0 to 100, along with a plain-language explanation
of anything suspicious it finds. It uses the character n-gram model developed
for Assignment 2 and supports an education campaign to help Australians protect
their personal information.

| Part | Folder | Technology |
|---|---|---|
| Front end | [`frontend/`](frontend/) | React 19, React Router 7, Recharts 2, Vite 8 |
| Back end | [`backend/`](backend/) | FastAPI, Pydantic 2, scikit-learn 1.9.1, Uvicorn |
| Security analysis | [`SECURITY.md`](SECURITY.md) | Threat model, defences, attack scripts and results |

## Security work for marking

The project focuses on these security requirements:

| Section | Selected work | Evidence |
|---|---|---|
| 2.7 Defence 1 | **Denial of service (Advanced)** | [SECURITY.md §2](SECURITY.md#2-defence-1--denial-of-service-advanced), `security/dos_attack.py` |
| 2.7 Defence 2 | **Unsafe model loading (Basic)** | [SECURITY.md §3](SECURITY.md#3-defence-2--unsafe-model-loading-basic), `security/model_tamper.py` |
| 2.8 Advanced attack | **Detection evasion** | [SECURITY.md §4](SECURITY.md#4-advanced-security--detection-evasion-section-28), `security/evasion_eval.py` |

We also hardened misconfiguration risks and vulnerable dependencies with
security headers, disabled documentation by default, and audited dependencies.
These are useful protections, but they are **not** the two defences selected
for marking.

For before-and-after demonstrations, you can disable defences using
`DISABLED_DEFENCES` in `backend/.env`. Available values are `dos`, `model`,
`evasion` and `hardening`.

## How it works

```
 Browser (React single-page app)
 ┌────────────────────────────────────────────┐
 │ UrlForm ── validateUrl (usability only)    │      localStorage
 │ ResultPanel · TrustGauge · WarningList     │◄────► history of checks
 │ Charts: confidence · warnings · history    │      (never sent anywhere)
 └──────────────────┬─────────────────────────┘
                    │ POST /api/assess {"url": "..."}   GET /api/health
                    │ (same origin; JSON only)
 ┌──────────────────▼─────────────────────────────────────────────────┐
 │ FastAPI back end (Uvicorn, 127.0.0.1:8000)                         │
 │                                                                    │
 │  Middleware, outermost first:                                      │
 │   SecurityHeaders ─► RequestContext ─► CORS ─► BodySizeLimit       │
 │   (CSP, nosniff…)    (request ID,        (own     (8 KB, before    │
 │                       JSON 500)           origins)  parsing)       │
 │                                                                    │
 │  Pydantic validation (AssessRequest) ─► URL length limit (2,048)   │
 │        │                                                           │
 │        ▼                                                           │
 │  InferenceGate: 2 worker threads + 8 queue places, else 503        │
 │        │                                                           │
 │        ▼                                                           │
 │  assess():  normalise_url ─► model.predict_proba ─► explain rules  │
 │             (evasion          (TF-IDF char 2–5-grams  (url_        │
 │              defence)          + SGD, log loss)        indicators) │
 │                                                                    │
 │  Startup: SHA-256 check ─► joblib.load(MODEL_FINAL.joblib), once   │
 │  Also serves frontend/dist (the built React app) at /              │
 └────────────────────────────────────────────────────────────────────┘
```

The back end analyses the submitted address as text; it never fetches or
resolves it. There is no database, either: each user's check history stays in
their own browser.

## Run PhishCheck

You'll need **Python 3.14** (tested with 3.14.7) and **Node.js 22.12 or newer**
(tested with 26.13). The commands below are for Windows PowerShell. On
macOS/Linux, activate the virtual environment with
`source .venv/bin/activate` and use `cp` instead of `copy`.

### 1. Set up the back end

From the project folder, create and activate a virtual environment, install the
back-end packages, and copy the example settings file:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

### 2. Configure the trained model

The server needs `backend/models/MODEL_FINAL.joblib` and its SHA-256 hash in
`backend/.env`. It will not load a model if the hash does not match. See
[SECURITY.md](SECURITY.md) for details.

**Use the included model (recommended).** The submission includes
`backend/models/MODEL_FINAL.joblib` (0.3 MB). Add this hash to `backend/.env`:

```
MODEL_SHA256=04b478c5fd5ee801e08499f7e32ef4bee92c6ce954f5b1d69767e8436a3d26c7
```

To check the hash yourself, run `python -m scripts.hash_model` from the
`backend/` directory.

**Download the model (only if the file is missing).** If the model is hosted
separately, add its `https://` address as `MODEL_URL` in `backend/.env`, and
set `MODEL_SHA256` to the hash above. Then run
`python -m scripts.download_model`. The script removes the downloaded file if
its hash doesn't match.

**Train a new model.** Use the scikit-learn version pinned by this back end:
pickled models are only reliably loaded by the version that created them.

1. Put the Assignment 2 code in a folder (called `assignment2-pipeline/`
   below). Create a virtual environment there, install `pandas` and
   `tldextract`, and save the raw datasets under `data/original_data/`. Check
   the Assignment 2 README for dataset names and links.
2. Use Assignment 2's cleaning functions (`unify_labels`, `clean_combined`,
   `apply_label_fixes`) to build the training table. The 50 engineered
   features aren't needed because this model only reads the URL:

   ```bash
   assignment2-pipeline\.venv\Scripts\python backend\scripts\build_training_table.py assignment2-pipeline assignment2-pipeline\data\combined_data\training_table.csv
   ```

3. From `backend/`, with its virtual environment active, train the model:

   ```bash
   python -m scripts.train_model "..\assignment2-pipeline\data\combined_data\training_table.csv"
   ```

   Training takes about 2.5 minutes. It saves
   `backend/models/MODEL_FINAL.joblib` and prints a `MODEL_SHA256=...` line.
   Copy that line into `backend/.env`.

The included model was trained on 684,806 URLs: 449,866 from the Mendeley
dataset (23% phishing) and 234,940 from PhiUSIIL (43% phishing), cleaned using
the Assignment 2 process. The Kaggle dataset wasn't used because it requires a
Kaggle account to download. If `malicious_phish.csv` is available,
`build_training_table.py` includes it and applies the Assignment 2 label
fixes.

The model's settings are unchanged from Assignment 2: TF-IDF over character
2–5-grams with a logistic-loss SGD classifier. Accuracy isn't assessed in this
assignment, so the model is treated as a black box.

### 3. Build the front end

From `backend/`, move to `frontend/`, install the exact versions in
`package-lock.json`, and build the app:

```bash
cd ../frontend
npm ci
npm run build
```

### 4. Start the app

Start the server from `backend/`:

```bash
cd ../backend
python run.py
```

Then open **http://127.0.0.1:8000**. The back end serves both the API and the
built front end from the same address.

### Run in development mode

For a faster front-end workflow, run `python run.py` in `backend/` and
`npm run dev` in `frontend/` in separate terminals. Open
http://localhost:5173. Vite reloads the page when you save changes and forwards
`/api` requests to the back end on port 8000.

To try the front end without starting the back end, run `npm run dev:mock` from
`frontend/`. It displays simulated results.

## Run tests and audits

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest
python -m pip_audit -r requirements.txt -r requirements-dev.txt
cd ../frontend
npm audit
```

## API documentation

FastAPI can generate interactive API documentation at **`/docs`**. It's
disabled by default to reduce the risk of misconfiguration. To turn it on for
development:

1. Set `ENABLE_DOCS=true` in `backend/.env`.
2. Restart the server with `python run.py`, then visit
   **http://127.0.0.1:8000/docs**.

Each endpoint includes a description, example requests (select one from the
**Examples** list after **Try it out**) and example success and error
responses. The `/docs` page has a more permissive Content Security Policy so
Swagger UI can load from its CDN; other pages keep the stricter policy.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/assess` | Scores one URL. Send `{"url": "..."}` (up to 2,048 characters; body up to 8 KB). The response includes the trust score, phishing probability, prediction, normalised URL analysed by the model, and explained warnings. |
| `GET` | `/api/health` | Reports whether the server is running and the model is loaded. The front end checks this on startup so it can warn you if the back end is unavailable. |

Errors use a consistent JSON format and don't expose stack traces or internal
details:

```json
{"error": {"code": "invalid_input", "message": "URL cannot be empty.",
           "details": [{"field": "url", "message": "URL cannot be empty."}],
           "request_id": "8e0a5c0dbdc24f41"}}
```

| Status | Code | When it occurs |
|---|---|---|
| 422 | `invalid_input` / `invalid_url` | The URL is empty, too long, contains spaces, has unknown fields, or the JSON is invalid |
| 413 | `payload_too_large` | The request body is over 8 KB (checked before parsing, even if `Content-Length` is missing) |
| 404 / 405 | `not_found` / `method_not_allowed` | The endpoint doesn't exist or the HTTP method is wrong |
| 503 | `service_busy` | The inference queue is full; the response includes `Retry-After` |
| 500 | `internal_error` | Something unexpected happened; details are logged on the server only |

## Threat model at a glance

**What we're protecting:** service availability, the integrity of phishing
verdicts, the server that loads the model, and the privacy of the URLs people
check.

**Who might attack it:** anyone who can reach the API. There are no accounts,
so every caller is anonymous and untrusted. Attacks can target the API
directly, not just the user interface.

**Entry Points:** `POST /api/assess`, `GET /api/health`, the static
front-end files, and the model file on disk.

| Risk | Applies? | How it's handled |
|---|---|---|
| Denial of service | Yes | **Defence 1.** Request-body and URL size limits, inference moved off the event loop, and a bounded queue that returns 503 when full |
| Unsafe model loading | Yes | **Defence 2.** The server checks the model's SHA-256 before `joblib.load`, refuses to start if it doesn't match, and unpickles the verified bytes |
| Detection evasion (look-alike letters, invisible characters, encodings) | Yes | **Advanced attack.** Unicode normalisation before analysis; look-alike host names are capped at trust 5 |
| Misconfiguration / vulnerable dependencies | Yes | Hardened, but not selected for marking: security headers, docs disabled by default, no server banner, strict CORS, and audited pinned dependencies |
| Missing rate limiting | Yes | Partly covered by the global admission gate; per-client limits aren't implemented |
| Command injection, SQL injection, file upload, SSRF, broken access control | No | The app doesn't run shell commands, use a database, accept uploads, fetch submitted URLs, or have accounts |

See [SECURITY.md](SECURITY.md) for the full risk table, rationale, measurements
and trade-offs.

## Pinned dependency versions

The back-end dependencies, including transitive dependencies, are pinned in
`backend/requirements.txt`:

| Package | Version | Package | Version |
|---|---|---|---|
| fastapi | 0.162.0 | scikit-learn | 1.9.1 |
| starlette | 1.10.0 | numpy | 2.5.4 |
| pydantic | 2.14.2 | scipy | 1.18.1 |
| pydantic_core | 2.50.2 | joblib | 1.6.0 |
| uvicorn | 0.54.0 | threadpoolctl | 3.7.0 |
| python-dotenv | 1.2.4 | idna | 3.20 |
| anyio | 4.16.0 | httptools | 0.9.0 |
| h11 | 0.16.0 | watchfiles | 1.3.0 |
| click | 8.5.0 | websockets | 17.4 |
| annotated-doc | 0.0.5 | PyYAML | 6.0.3 |
| annotated-types | 0.8.0 | colorama | 0.4.6 |
| typing-inspection | 0.4.4 | typing_extensions | 4.16.0 |

Development-only packages are listed in `backend/requirements-dev.txt`:
pytest 9.2.0, httpx 0.28.1, httpcore 1.0.9, pip-audit 2.10.1,
certifi 2026.10.23, iniconfig 2.3.1, packaging 26.3, pluggy 1.7.0 and
Pygments 2.21.0.

The front-end versions are set in `frontend/package.json`; `package-lock.json`
pins the full dependency tree:

| Package | Version |
|---|---|
| react | 19.3.1 |
| react-dom | 19.3.1 |
| react-router-dom | 7.18.5 |
| recharts | 2.15.4 |
| @fontsource-variable/inter | 5.3.0 (self-hosted Inter typeface, so no font CDN is needed) |
| vite (dev) | 8.3.5 |
| @vitejs/plugin-react (dev) | 6.2.1 |

**Runtimes:** Python 3.14.7 and Node.js 26.13.0 (Node.js 22.12 or newer is
required).

## Configuration

All settings are in `backend/.env`; see
[`.env.example`](backend/.env.example) for the available options. There are
no deployment-specific settings or secrets in the source code, and the front
end doesn't contain secrets. The `.env` file is git-ignored and isn't included
in the submission ZIP.

## Use of generative AI

We used **Claude Code** (Anthropic, model Claude Opus 5.5) to help debug issues
and generate ideas during this assignment. The group evaluated those ideas and
made the final decisions about the application.

## References

Andersson, R. (2026) *Inter* [Typeface]. Available at: https://rsms.me/inter/ (Accessed: 3 November 2026).

Anthropic (2026) *Claude Code* [Computer software]. Available at: https://claude.com/claude-code (Accessed: 3 November 2026).

Costello, A. (2003) *Punycode: A Bootstring encoding of Unicode for Internationalized Domain Names in Applications (IDNA)*. RFC 3492. Internet Engineering Task Force. Available at: https://www.rfc-editor.org/rfc/rfc3492 (Accessed: 3 November 2026).

Fielding, R., Nottingham, M. and Reschke, J. (eds) (2022) *HTTP Semantics*. RFC 9110. Internet Engineering Task Force. Available at: https://www.rfc-editor.org/rfc/rfc9110 (Accessed: 3 November 2026).

Gabrilovich, E. and Gontmakher, A. (2002) 'The homograph attack', *Communications of the ACM*, 45(2), p. 128.

Kaitholikkal, J.K.S. and B, A. (2024) *Phishing URL dataset*. Mendeley Data, V1. doi: 10.17632/vfszbj9b36.1.

Meta Platforms (2026) *React* [Computer software]. Available at: https://react.dev (Accessed: 3 November 2026).

Mozilla (2026) *Content Security Policy (CSP)*. MDN Web Docs. Available at: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP (Accessed: 3 November 2026).

OWASP Foundation (2021) *OWASP Top 10:2021*. Available at: https://owasp.org/Top10/ (Accessed: 3 November 2026).

OWASP Foundation (2023) *OWASP API Security Top 10 2023*. Available at: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ (Accessed: 3 November 2026).

Pedregosa, F., Varoquaux, G., Gramfort, A., Michel, V., Thirion, B., Grisel, O., Blondel, M., Prettenhofer, P., Weiss, R., Dubourg, V., Vanderplas, J., Passos, A., Cournapeau, D., Brucher, M., Perrot, M. and Duchesnay, É. (2011) 'Scikit-learn: Machine learning in Python', *Journal of Machine Learning Research*, 12, pp. 2825–2830.

Prasad, A. and Chandra, S. (2024) 'PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning', *Computers & Security*, 136, 103545. doi: 10.1016/j.cose.2023.103545.

Ramírez, S. (2026) *FastAPI* [Computer software]. Available at: https://fastapi.tiangolo.com (Accessed: 3 November 2026).

Recharts Group (2026) *Recharts* [Computer software]. Available at: https://recharts.org (Accessed: 3 November 2026).

Siddhartha, M. (2021) *Malicious URLs dataset*. Kaggle. Available at: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset (Accessed: 3 November 2026).

Unicode Consortium (2025) *Unicode Technical Standard #39: Unicode Security Mechanisms*. Available at: https://www.unicode.org/reports/tr39/ (Accessed: 3 November 2026).
