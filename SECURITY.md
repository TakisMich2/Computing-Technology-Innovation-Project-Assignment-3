# Threat model and security measures

The front end design will support users to enter URLs easily (and supporting those with general accessibility requirements), however the back end will be responsible for the handling of security. The attacks described here may call the API directly using curl or Python scripts, just as a potential (real-world) threat actor may. 

## 1. Threat model

**Protected resources -> What are we aiming to protect across the application?:** 
- Service availability
- Accuracy + integrity of the service's verdicts
- Server responsible for loading model itself
- Privacy of URLs users are checking (consider whether 'History' tab's function (local storage) prevails over the security flaws it exposes to attackers/threat actors? -> Pain point to resolve)

**Threat actor profile/requirements:**  
- anyone who can reach the API
- Since there are no accounts, every caller is anonymous and must be treated as untrusted (for a full/strategic solution, we would consider integrating with a light IdP to remediate this, potentially Auth0 due to its free licensing? Due to the constraints/limits of this project we have not implemented this.)

**Entry Points:** `POST /api/assess`, `GET /api/health`, the static front-end files, and the model file on disk -

| Risk and level| Applies? | Why / what we do |
|---|---|---|
| **Denial of service** (Advanced) | **Yes, chosen defence 1** | Inference is CPU work whose cost grows with input length, and FastAPI sets no limits.  |
| **Unsafe model loading** (Basic) | **Yes, chosen defence 2** | The server loads a joblib file, which can run code hidden inside it, and the model can arrive by download script.  |
| Misconfiguration & vulnerable dependencies (Intermediate) | Yes | Applies to every application. Hardened, but not a marked defence. |
| Missing rate limiting (Basic) | Yes | Not chosen but partially covered by the global admission gate in s2, which limits total load but not any one particular client's share. A per-client limit would be the next step. |
| Command injection (Basic) | No | The back end never runs a system command (no `whois`, `dig` or shell calls). |
| SQL injection (Intermediate) | No | We do not leverage a database.. Analysis history utilises local storage for the user. (`localStorage`). |
| Unsafe file upload (Intermediate) | No | The API accepts no files, only a JSON body capped at 8 KB. |
| SSRF (Advanced) | No | The submitted URL is analysed as text. The back end never fetches it, resolves it or follows redirects, so it cannot be pointed at internal addresses. This is a deliberate design choice, particularly given the nature of the website is to avoid the risks posed by navigating to potential phishing sites.  |
| Broken access control (Advanced) | No | There's no user accounts or per-user records. |

## 2. Defence 1: Denial of service (Advanced)

**Risk description**  
A request can be cheap to send but expensive for the server to process. Model inference (TF-IDF over character 2–5-grams) takes about 4 µs
per character, under 10 ms for a 2,048-character URL, but about 20 s for a5 MB URL. If inference runs inside an `async def` endpoint, it blocks the event loop and makes other users wait. A flood can also leave the server with an unbounded queue of work.

**Defence** (`app/security.py`, `app/model_service.py`, `app/main.py`):

1. Body size limit before parsing: Pure-ASGI middleware rejects bodies over 8 KB with 413. It works on the raw byte stream, so it also stops chunked uploads that lie about or omit `Content-Length`. Nothing oversized is buffered or parsed.
2. Input length limit: URLs over 2,048 characters are rejected with 422, which caps the cost of a single inference at under 10 ms.
3. Inference off the event loop:The model runs in a dedicated two-thread pool, so the server keeps accepting and answering other requests (such as `/api/health`) whilst it works.
4. Admission gate with fast rejection: At most 2 running plus 8 waiting inferences, with a 2 s queue timeout. Anything beyond that gets an immediate 503 with `Retry-After` instead of queueing until the server freezes.

In phase 1, the script sends a 5 MB URL whilst a 'normal user' checks a regular URL every 100 ms. In phase 2, it sends 300 maximum-size requests at once whilst another client checks `/api/health`. The results are saved in
`security/results/`.

**Results** (trained model `MODEL_FINAL.joblib`, Alyssa's (my) Windows laptop, client and server on the same machine, 3 November 2026)

| | Undefended | Defended |
|---|---|---|
| 5 MB request | 200 after **20,670 ms** | **413 after 37 ms** |
| Normal user's slowest response during that request | **20,511 ms** (blocked) | 63 ms |
| Flood:300x requests | all 300 accepted and processed | 13 answered, 287 rejected with 503 |
| Flood: total time to answer all 300 | 6,155 ms | 4,435 ms |
| `/api/health` slowest response during the flood | 3,900 ms | 2,168 ms |


**Trade-offs & Discovered limitations**  
URLs longer than 2,048 characters can't be checked. Browsers and most servers have similar URL limits, so this is highly unlikely to affect
ordinary links but still worth noting as a limitation. During a burst, some genuine users may get a 'busy, try again' response (503) rather than a delayed result. We chose a quick, clear refusal over letting the site freeze. The two-thread pool also limits throughput on larger machines.

During the flood, /api/health latency improves somewhat modestly. On one laptop (assume even if this is a public-facing website, we are still hosting this on my/equivalent basic/personal-use machinery), accepting 300 connections in a single Python process is itself a bottleneck. Handling that volume would require a reverse proxy or protection from the hosting provider. -> Out of scope for current self-hosted solution

## 3. Defence 2: Unsafe model loading (Basic)

**Risk description**  
joblib.load uses pickle, which can run code whilst still rebuilding an object. If an attacker can replace the model file, for example, by tampering
with a download, sharing a malicious file, or writing to the server's folder directly they could make that code run with the server's permissions when it starts.  
The script `security/model_tamper.py` creates a working copy of ourmodel with hidden code that runs first, then returns real model. The server starts and gives presumably normal looking results. Our harmless payload writes`security/results/PWNED.txt` for the purposes of this project and to show what could be impacted, but a real attack could read .env and install a backdoor or alter verdicts.

**Defence** (`app/model_service.py`, `load_verified_model`):

1. The trusted SHA-256 of the model lives in MODEL_SHA256 (in backend/.env, and published in the README). It is configuration, kept out of the model file.
2. At startup the file is read once and then its hash is compared with hmac.compare_digest, and on any mismatch the server refuses to start. `joblib.load` is never called on an unverified file.
3. The bytes that were hashed are the bytes that are unpickled (from memory). Swapping the file between the check and the load has no effect.
4. A missing or malformed MODEL_SHA256 (empty, or shortened to a prefix) also refuses to start, so the check cannot be quietly skipped. Files over 200 MB are refused before they are read.
5. The model is loaded once at startup, NEVER per request. a file replaced while the server runs is only loaded, and checked, at the next start.
6. scripts/download_model.py applies the same rule to downloads: https only, and the file is deleted unless its hash matches.

***  
run `python -m security.model_tamper build`, 

| Case | Result | Hidden code ran? |
|---|---|---|
| Undefended: plain joblib.load of the tampered file | loaded | **yes** |
| Tampered file, real MODEL_SHA256| refused -> hash mismatch| no |
| Tampered file, MODEL_SHA25  left empty | refused -> hash not set| no |
| Tampered file, hash shortened to 12 characters | refused -> must be 64 hex characters | no |
| File swapped on disk after the hash check (test) | the verified bytes are loaded, not the swap | no |
| File over the size limit (test) | refused before reading | no |
| Genuine model | loaded | no |
| *Limit:* attacker can also rewrite MODEL_SHA256 in .env | loaded | yes |

**Trade offs and discovered limitations** 
Verifying the model adds about 0.5 ms to startup (40.3 ms compared with 39.8 ms to load the 0.3 MB model). After retraining, you will need to copy the new hash into .env and unless and until then the server won't start.  
  
We prefer the short interruption to loading a file we can't verify in the first instance. The one-time read uses about as much memory as the model file (0.3 MB) and should not be material or of any noticeable impact to end users anyway.

## 4. Advanced security: Detection evasion

**Risk description**  
Small imperceptible changes can alter the URL the model analyses. Because it learned character n-grams from plain-ASCII URLs, an attacker could
try any of the below methods -

| Attack | Example |
|---|---|
| `homoglyph_host_3` | Up to 3 hostname letters swapped for Cyrillic look-alikes (`pаypal`) |
| `homoglyph_everywhere` | Every swappable letter in the URL swapped |
| `fullwidth_host` | Hostname in full-width letters (`ｐａｙｐａｌ.com`) |
| `zero_width` | A zero-width space after every third character |
| `punycode_homoglyph_host` | The look-alike hostname in its `xn--` form |
| `percent_encoded_host` | Every hostname letter percent-encoded |

Browsers can resolve full-width, zero-width and percent-encoded forms to thesame site. Look-alike domains are also a familiar phishing trick. In each case, the link can still work for the person who clicks it.

**Defence: normalise URLs before analysis**
(`app/normalise.py`, applied in `app/assess.py`):

1. Remove invisible characters (zero-width, BOM, soft hyphen, bidi controls).
2. Apply Unicode NFKC normalisation (full-width and other compatibility forms become ASCII).
3. Percent-decode and lower-case the hostname, and decode xn-- labels.
4. Map Cyrillic and Greek look-alikes to their Latin "skeleton" (based on Unicode UTS #39 confusables), but only within words that are disguises: they mix Latin with look-alikes, or consist entirely of look-alikes. A genuine Russian domain such as пример.рф is left alone.
5. Re-encode anything still non-ASCII as a browser would (punycode host, percent-encoded path).
6. A hostname disguised with look-alike letters is capped at a trust score of 5. No real site mixes alphabets to imitate another, and the skeleton of pаypal.com is paypal.com, which the model would otherwise rate safe.

The result explains each normalisation step and shows the address the browser would actually visit.

Measure the effect using our trained model + dataset:

```bash
python -m security.evasion_eval --csv "path\to\CODECREATED_final_cleaned_csv_phishing.csv" --sample 1000
```


**Results**  
(trained model, 2,000 phishing and 2,000 benign URLs sampled from the training table with seed 432; 1,913 of the phishing URLs are detected
unmodified.  
raw output in `security/results/evasion.json`):

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

(URL counts differ slightly because some URLs have no letter the attack can change, e.g. a hostname that is an IP address.)

**What the results show:**
- Swapping a few hostname letters for look-alikes only rarely fooled the model (2%), since the rest of the URL still looked like or had substnatial elements of phishing.
- Disguising more of the URL was more effective -> nearly a third of detected phishing links were classified as 'likely benign' when every letter was swapped, and one in six when the hostname used full-width letters. 
- After normalisation, the model analyses the URL without those disguises, and look-alike hostnames are capped at trust 5. 
- Normalisation didn't change detection or false-positive rates for ordinary URLs.

**Limits:** 
- The sample came from the model's training data, so the 95.7% detection rate is likely optimistic
- The Kaggle dataset wasn't used to train this model (see the README)
- We tested only the six attacks listed above

**Trade-offs:**  
- Some legitimate internationalised domains may use look-alike letters, for example in brand names, and could be flagged as high
risk unfairly. If this were a live solution, it may be unfairly prejudiced to non-English speaking countries/their emerging technologies
- The mapping currently covers Cyrillic and Greek, but not other scripts such as Armenian, and will need updates as new tricks emerge
- Normalisation adds well under a millisecond per request
- The front end accepts non-ASCII input so the server can warn about a disguised link instead of rejecting it outright

## 6. Security hygiene checklist

| Requirement | How it is met |
|---|---|
| User input never rendered as HTML |React escapes all text: i.e. the code has no dangerouslySetInnerHTML, innerHTML, window.open  or window.location assignments, and no user-controlled href. React 19 also neutralises javascript:  URLs. The API returns JSON only. CSV export prefixes formula characters (= + - @) to stop spreadsheet injection. |
| Size limits enforced on the back end | 8 KB request body (middleware) and 2,048-character URL (422). No file uploads. |
| CORS allows only our front end | ALLOWED_ORIGINS lists explicit origins; * is refused at startup, tested in test_cors_allows_only_the_front_end. In production the front end is served from the same origin, so no cross-origin access is needed at all. |
| Secrets out of source code | All configuration comes from environment variables or backend/.env (git-ignored). The model hash is configuration, rather than a secret, but lives there too so a new model needs no code change. The app has no passwords or API keys.If this were a live solution a secrets management platform would be best practice (i.e. Hashicorp) |
