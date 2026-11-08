# PhishCheck – Threat model and security measures

The front end helps users enter URLs, but the back end is responsible for
security. The attacks described here call the API directly using curl or
Python scripts, just as an attacker could.

For the demonstration video, each defence can be switched off using
`DISABLED_DEFENCES` in `backend/.env` (`dos`, `model`, `evasion`, `hardening`).
The server logs a warning at startup if any defence is disabled.

**Selected for marking:** denial-of-service defence (§2), unsafe model-loading
defence (§3), and detection-evasion attack (§4). Section 5 covers additional
hardening that we consider good practice, but it isn't one of the two selected
defences.

## 1. Threat model

**What we're protecting:** the service's availability, the accuracy and
integrity of its verdicts, the server that loads the model, and the privacy of
the URLs people check.

**Who might attack it:** anyone who can reach the API. Since there are no
accounts, every caller is anonymous and must be treated as untrusted.

**Entry Points:** `POST /api/assess`, `GET /api/health`, the static
front-end files, and the model file on disk.

| Risk (level) | Applies? | Why / what we do |
|---|---|---|
| **Denial of service** (Advanced) | **Yes – chosen defence 1** | Inference is CPU work whose cost grows with input length, and FastAPI sets no limits. See §2. |
| **Unsafe model loading** (Basic) | **Yes – chosen defence 2** | The server loads a joblib file, which can run code hidden inside it, and the model can arrive by download script or from a teammate. See §3. |
| Misconfiguration & vulnerable dependencies (Intermediate) | Yes | Applies to every application. **Also hardened, but not one of the two marked defences.** See §5. |
| Missing rate limiting (Basic) | Yes | Not chosen. Partly covered by the global admission gate in §2, which limits total load but not any one client's share. A per-client limit would be the next step. |
| Command injection (Basic) | No | The back end never runs a system command (no `whois`, `dig` or shell calls). |
| SQL injection (Intermediate) | No | There is no database. Analysis history is kept only in the user's own browser (`localStorage`). |
| Unsafe file upload (Intermediate) | No | The API accepts no files, only a JSON body capped at 8 KB. |
| SSRF (Advanced) | No | The submitted URL is analysed **as text only**. The back end never fetches it, resolves it or follows redirects, so it cannot be pointed at internal addresses. This is a deliberate design choice. |
| Broken access control (Advanced) | No | There are no user accounts or per-user records. |

## 2. Defence 1 – Denial of service (Advanced)

**The risk.** A request can be cheap to send but expensive for the server to
process. Model inference (TF-IDF over character 2–5-grams) takes about 4 µs
per character: under 10 ms for a 2,048-character URL, but **about 20 s for a
5 MB URL**. If inference runs inside an `async def` endpoint, it blocks the
event loop and makes other users wait. A flood can also leave the server with
an unbounded queue of work.

**Defence** (`app/security.py`, `app/model_service.py`, `app/main.py`):

1. **Body size limit before parsing.** Pure-ASGI middleware rejects bodies over 8 KB with 413. It works on the raw byte stream, so it also stops chunked uploads that lie about or omit `Content-Length`. Nothing oversized is buffered or parsed.
2. **Input length limit.** URLs over 2,048 characters are rejected with 422, which caps the cost of a single inference at under 10 ms.
3. **Inference off the event loop.** The model runs in a dedicated two-thread pool, so the server keeps accepting and answering other requests (such as `/api/health`) while it works.
4. **Admission gate with fast rejection.** At most 2 running plus 8 waiting inferences, with a 2 s queue timeout. Anything beyond that gets an immediate **503 with `Retry-After`** instead of queueing until the server freezes.

**Try the demonstration** with the server running:

```bash
python -m security.dos_attack --label defended
# set DISABLED_DEFENCES=dos in .env, restart the server, then:
python -m security.dos_attack --label undefended
```

In phase 1, the script sends a 5 MB URL while a "normal user" checks a regular
URL every 100 ms. In phase 2, it sends 300 maximum-size requests at once while
another client checks `/api/health`. The results are saved in
`security/results/`.

**Results** (trained model `MODEL_FINAL.joblib`, Windows laptop, client and
server on the same machine, 3 November 2026; raw output in
`security/results/dos-*.json`):

| | Undefended | Defended |
|---|---|---|
| 5 MB request | 200 after **20,670 ms** | **413 after 37 ms** |
| Normal user's slowest response during that request | **20,511 ms** (blocked) | 63 ms |
| Flood of 300 requests | all 300 accepted and processed | 13 answered, **287 rejected with 503** |
| Flood: total time to answer all 300 | 6,155 ms | 4,435 ms |
| `/api/health` slowest response during the flood | 3,900 ms | 2,168 ms |

**Other cases tested:** request bodies with a missing or misleading
`Content-Length` (test `test_body_size_limit_without_content_length`); a URL
under the byte limit but over the character limit (422); bursts of small
requests (503 admission gate); and a slow request that fills a worker (queue
timeout, then 503). We also timed 2,048-character inputs designed to make the
regular expressions backtrack. These included repeated hyphens, dots, digits,
percent escapes, query parameters, `@` signs, slashes, `xn--` labels,
sensitive words, zero-width characters and Cyrillic characters. The slowest
took 36 ms, so none of the tested inputs within the limit took unusually long.

**Trade-offs.** URLs longer than 2,048 characters can't be checked. Browsers
and most servers have similar URL limits, so this is unlikely to affect
ordinary links. During a burst, some genuine users may get a "busy, try again"
response (503) rather than a delayed result. We chose a quick, clear refusal
over letting the site freeze. The two-thread pool also limits throughput on
larger machines; increase `INFERENCE_WORKERS` if needed.

**Limitations.** During the flood, `/api/health` latency improves only
modestly. On one laptop, accepting 300 connections in a single Python process
is itself a bottleneck. Handling that volume would require a reverse proxy or
protection from the hosting provider. Distributed attacks are outside the
scope of the assignment.

## 3. Defence 2 – Unsafe model loading (Basic)

**The risk.** `joblib.load` uses pickle, which can run code while rebuilding
an object. If an attacker can replace the model file—for example, by tampering
with a download, sharing a malicious file, or writing to the server's
folder—they could make that code run with the server's permissions when it
starts. The script `security/model_tamper.py` creates a working copy of our
model with hidden code that runs first, then returns the genuine model. The
server starts and gives normal-looking results. Our harmless payload writes
`security/results/PWNED.txt`; a real attack could read `.env`, install a
backdoor or alter verdicts.

**Defence** (`app/model_service.py`, `load_verified_model`):

1. The trusted SHA-256 of the model lives in `MODEL_SHA256` (in `backend/.env`, and published in the README). It is configuration, kept out of the model file.
2. At startup the file is read **once**, its hash is compared with `hmac.compare_digest`, and on any mismatch the server **refuses to start**. `joblib.load` is never called on an unverified file.
3. The bytes that were hashed are the bytes that are unpickled (from memory). Swapping the file between the check and the load has no effect.
4. A missing or malformed `MODEL_SHA256` (empty, or shortened to a prefix) also refuses to start, so the check cannot be quietly skipped. Files over 200 MB are refused before they are read.
5. The model is loaded once at startup, never per request; a file replaced while the server runs is only loaded, and checked, at the next start.
6. `scripts/download_model.py` applies the same rule to downloads: https only, and the file is deleted unless its hash matches.

**Try the demonstration:** run `python -m security.model_tamper build`, then:

| Step | Undefended (`DISABLED_DEFENCES=model`) | Defended |
|---|---|---|
| `.env`: `MODEL_PATH=models/TAMPERED.joblib`, real `MODEL_SHA256` | | |
| `python run.py` | Server starts; logs "loading TAMPERED.joblib WITHOUT checking its hash" | **Server refuses to start**: "Model file hash does not match MODEL_SHA256 (expected 04b478c5fd5e…, got bd2642cc847c…)" |
| `curl -X POST http://127.0.0.1:8000/api/assess -H "Content-Type: application/json" -d "{\"url\":\"https://www.abc.net.au/news\"}"` | Normal answer (trust 96): the attack is invisible | No server to answer |
| `security/results/PWNED.txt` | **Created**: the hidden code ran | **Not created** |

**Variations** (`python -m security.model_tamper measure`, saved in
`security/results/model-tamper.json`, and `tests/test_model_loading.py`):

| Case | Result | Hidden code ran? |
|---|---|---|
| Undefended: plain `joblib.load` of the tampered file | loaded | **yes** |
| Tampered file, real `MODEL_SHA256` | refused (hash mismatch) | no |
| Tampered file, `MODEL_SHA256` left empty | refused (hash not set) | no |
| Tampered file, hash shortened to 12 characters | refused (must be 64 hex characters) | no |
| File swapped on disk after the hash check (test) | the verified bytes are loaded, not the swap | no |
| File over the size limit (test) | refused before reading | no |
| Genuine model | loaded | no |
| *Limit:* attacker can also rewrite `MODEL_SHA256` in `.env` | loaded | yes |

The final row shows the trust boundary, not a way around the check. Whoever
controls `.env` chooses which model is trusted. That's why the hash must come
from a trusted source, such as the README or the person who trained the model,
and not from the same place as the model file.

**Trade-offs.** Verifying the model adds about 0.5 ms to startup (40.3 ms
compared with 39.8 ms to load the 0.3 MB model, best of 20). After retraining,
you need to copy the new hash into `.env`; until then, the server won't start.
We prefer that short interruption to loading a file we can't verify. The
one-time read uses about as much memory as the model file (0.3 MB). The check
confirms the file matches the trusted hash; it doesn't confirm that the model
was trained well.

## 4. Advanced security – Detection evasion (section 2.8)

**The risk.** Small, hard-to-see changes can alter the URL the model analyses.
Because it learned character n-grams from plain-ASCII URLs, an attacker could
try:

| Attack | Example |
|---|---|
| `homoglyph_host_3` | Up to 3 hostname letters swapped for Cyrillic look-alikes (`pаypal`) |
| `homoglyph_everywhere` | Every swappable letter in the URL swapped |
| `fullwidth_host` | Hostname in full-width letters (`ｐａｙｐａｌ.com`) |
| `zero_width` | A zero-width space after every third character |
| `punycode_homoglyph_host` | The look-alike hostname in its `xn--` form |
| `percent_encoded_host` | Every hostname letter percent-encoded |

Browsers can resolve full-width, zero-width and percent-encoded forms to the
same site. Look-alike domains are also a familiar phishing trick. In each
case, the link can still work for the person who clicks it.

**Defence: normalise URLs before analysis**
(`app/normalise.py`, applied in `app/assess.py`):

1. Remove invisible characters (zero-width, BOM, soft hyphen, bidi controls).
2. Apply Unicode NFKC normalisation (full-width and other compatibility forms become ASCII).
3. Percent-decode and lower-case the hostname, and decode `xn--` labels.
4. Map Cyrillic and Greek look-alikes to their Latin "skeleton" (based on Unicode UTS #39 confusables), but only within words that are disguises: they mix Latin with look-alikes, or consist entirely of look-alikes. A genuine Russian domain such as `пример.рф` is left alone.
5. Re-encode anything still non-ASCII as a browser would (punycode host, percent-encoded path).
6. A hostname disguised with look-alike letters is capped at a trust score of 5. No real site mixes alphabets to imitate another, and the skeleton of `pаypal.com` *is* `paypal.com`, which the model would otherwise rate safe.

The result explains each normalisation step and shows the address the browser
would actually visit.

**Measure the effect** using your trained model and dataset:

```bash
python -m security.evasion_eval --csv "path\to\CODECREATED_final_cleaned_csv_phishing.csv" --sample 1000
```

The script samples phishing URLs that the model detects without modification,
applies each attack, then reports how many are classified as "likely benign"
before and after normalisation. It also reports detection and false-positive
rates on unchanged URLs, so you can see whether the defence affects ordinary
traffic. Results are saved in `security/results/evasion.json`.

**Results** (trained model, 2,000 phishing and 2,000 benign URLs sampled from
the training table with seed 432; 1,913 of the phishing URLs are detected
unmodified; raw output in `security/results/evasion.json`):

```bash
python -m security.evasion_eval --csv "..\assignment2-pipeline\data\combined_data\training_table.csv" --sample 2000 --seed 432
```

| Attack | URLs | Evasion before | Evasion after |
|---|---|---|---|
| homoglyph_host_3 | 1,870 | 2.0% | **0.0%** |
| homoglyph_everywhere | 1,913 | **31.4%** | **0.0%** |
| fullwidth_host | 1,913 | **16.8%** | **0.0%** |
| zero_width | 1,913 | 3.0% | **0.0%** |
| punycode_homoglyph_host | 1,870 | 2.5% | **0.0%** |
| percent_encoded_host | 1,871 | 1.9% | **0.0%** |
| *Unmodified traffic* | 2,000 + 2,000 | detection 95.7%, false positives 0.0% | detection 95.7%, false positives 0.0% |

(URL counts differ slightly because some URLs have no letter the attack can
change, e.g. a hostname that is an IP address.)

**What the results show.** Swapping a few hostname letters for look-alikes
only rarely fooled the model (2%), since the rest of the URL still looked like
phishing. Disguising more of the URL was more effective: nearly a third of
detected phishing links were classified as "likely benign" when every letter
was swapped, and one in six when the hostname used full-width letters. After
normalisation, the model analyses the URL without those disguises, and
look-alike hostnames are capped at trust 5. None of the tested attacks evaded
detection. Normalisation didn't change detection or false-positive rates for
ordinary URLs.

**Limits of the measurement.** The sample came from the model's training data,
so the 95.7% detection rate is likely optimistic. It's included as a baseline
for comparing the attacks, not as a measure of real-world performance. The
Kaggle dataset wasn't used to train this model (see the README), and we tested
only the six attacks listed above.

**Trade-offs and gaps.** Some legitimate internationalised domains may use
look-alike letters, for example in brand names, and could be flagged as high
risk. The mapping currently covers Cyrillic and Greek, not other scripts such
as Armenian, and will need updates as new tricks emerge. Normalisation adds
well under a millisecond per request. The front end accepts non-ASCII input so
the server can warn about a disguised link instead of rejecting it outright.

## 5. Additional hardening – misconfiguration and vulnerable dependencies (not marked)

**The risk.** Default settings can expose information and leave browser
protections disabled. Examples include missing security headers, publicly
available interactive API docs, an advertised server version, and libraries
with known vulnerabilities.

**Defence:**

| Item | What we did | Where |
|---|---|---|
| Security headers on every response, including errors | `Content-Security-Policy` (scripts and styles only from our own origin, no framing, no plugins), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` and `-Resource-Policy`; `Cache-Control: no-store` on API responses | `app/security.py` |
| Debug features off | `/docs` and `/openapi.json` disabled unless `ENABLE_DOCS=true` (when on, only `/docs` gets a looser CSP so Swagger UI can load from jsDelivr); no debug mode; errors never include stack traces | `app/main.py`, `app/errors.py`, `app/security.py` |
| No server fingerprint | Uvicorn's `Server` header removed | `run.py` |
| CORS | Only the configured front-end origins; a `*` value makes the server refuse to start | `app/config.py` |
| Privacy in logs | Request logs record method, path, status and time, never the submitted URL | `app/security.py` |
| Pinned dependencies | Every Python package pinned exactly (including transitive ones); `package-lock.json` with exact versions | `requirements*.txt`, `package.json` |
| Vulnerable dependencies | `npm audit` first reported **4 vulnerable packages (3 moderate, 1 high)**: esbuild through Vite 5 (dev server readable by any website, GHSA-67mh-4wv8-2f99) and React Router 6 (open redirect, GHSA-wrjc-x8rr-h8h6; constructor injection in SSR hydration, GHSA-337j-9hxr-rhxg). Fixed by upgrading to Vite 8.3.5 and React Router 7.18.5 (and React 19). Now `npm audit` reports **0 vulnerabilities** and `pip-audit` reports **no known vulnerabilities**. | `package.json` |

**Check the headers** with `curl -I http://127.0.0.1:8000/`. Set
`DISABLED_DEFENCES=hardening` to turn them off for comparison. We didn't run an
OWASP ZAP scan because this isn't one of the defences selected for marking.

**Trade-offs.** The strict CSP blocks inline scripts and styles, so components
need to use stylesheets and DOM style properties (as ours already do).
Disabling `/docs` is less convenient for developers. Pinned dependencies also
need deliberate updates, so security fixes won't arrive automatically; run
both dependency audits regularly.

## 6. Security hygiene checklist (section 2.3)

| Requirement | How it is met |
|---|---|
| User input never rendered as HTML | React escapes all text. The code has no `dangerouslySetInnerHTML`, `innerHTML`, `window.open` or `window.location` assignments, and no user-controlled `href`. React 19 also neutralises `javascript:` URLs. The API returns JSON only. CSV export prefixes formula characters (`= + - @`) to stop spreadsheet injection. |
| Size limits enforced on the back end | 8 KB request body (middleware) and 2,048-character URL (422). There are no file uploads. |
| CORS allows only our front end | `ALLOWED_ORIGINS` lists explicit origins; `*` is refused at startup; tested in `test_cors_allows_only_the_front_end`. In production the front end is served from the same origin, so no cross-origin access is needed at all. |
| Secrets out of source code | All configuration comes from environment variables or `backend/.env` (git-ignored). The model hash is configuration, not a secret, but lives there too so a new model needs no code change. The app has no passwords or API keys. |
