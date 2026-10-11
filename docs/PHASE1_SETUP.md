# Secure local setup and verification

All detectors and extension features remain enabled. Python 3.11 is the tested interpreter. Install `backend/requirements.txt` in your own virtual environment; this phase used the already installed compatible packages rather than replacing the user's environment.

1. Open `chrome://extensions`, enable Developer mode and load the `extension` directory unpacked. Open **Details → Extension options** (or **Connection settings** in the popup). Copy the exact extension origin shown there.
2. In PowerShell, from the project root:

   ```powershell
   $env:PHISHGUARD_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
   $env:PHISHGUARD_EXTENSION_ORIGINS = 'chrome-extension://YOUR_32_LETTER_EXTENSION_ID'
   $env:FLASK_ENV = 'production'
   Write-Host $env:PHISHGUARD_API_TOKEN  # Copy this private value into extension options.
   python backend/run.py
   ```

   Copy the displayed token into extension options; do not include it in screenshots or shared terminal logs. Alternatively generate it once, save it privately, and set that same value in the backend environment and extension options. `backend/.env.example` is a reference, not an automatically loaded file. Never commit your actual token.
3. In extension options, use `http://127.0.0.1:5000/api/analyze`, paste the token and select **Save connection**, then **Test connection**. The token is stored in IndexedDB belonging to the extension origin. Content scripts' IndexedDB belongs to the visited origin, not the extension. Non-secret settings use extension local storage; access is further restricted when the browser provides setAccessLevel. Visited websites/content scripts cannot retrieve it through the extension's settings messages. It is not an encrypted secret store against other programs running as the same OS user.
4. The server binds only to `127.0.0.1`. `/health` provides public local liveness; all analysis/status/info routes require `Authorization: Bearer <token>`. Exact configured extension origins are allowed, arbitrary origins are rejected even with a token. Requests without Origin still require authentication. CORS is not authentication.

Do not expose this local development server to the LAN or Internet. Debug is off by default. The project does not fetch URLs being analyzed. MiniLM loads only local files.

## Saved artifacts

`models/saved/lgbm_url_model.txt` is tracked. The loader normalizes CRLF to LF **in memory**, because LightGBM's native format contains byte offsets. It never rewrites the file.

MiniLM also requires `models/saved/nlp_phish_model/model.safetensors`. Git intentionally excludes this large file. In this workspace it was recovered from the user's pre-reset backup, after checking that its model/tokenizer configuration matched the repository. A fresh checkout on another machine must receive this same trained artifact through a trusted private copy; no download or training happens automatically. Expected SHA-256:

`fd7e4c1e3452ad211703596f43ead4a14c4d4d217b066aaa1a775ee4cd0eb38e`

## Scoring, failure and cache policy

- Scores range from 0–100. Safe: `<=30`; Suspicious: `>30` and `<=70`; Dangerous: `>70`.
- Full analysis uses URL 30%, NLP 40%, DOM 30%, truncating the result to an integer. Unavailable detectors do not contribute zero: weights are normalized over available scores. URL-only uses URL 100%; URL+NLP uses 30/70 and 40/70; URL+DOM uses 50/50.
- The existing URL `>=90` floor of 90 is preserved. URL `>=50` still triggers precautionary warning/redirect, even if the combined category is only Suspicious. Full combined scores `>70` also trigger a warning. Warning pages explicitly identify whether the displayed blocking score is the URL or combined score.
- Each detector reports `ok`, `not_run`, `failed`, or `timed_out`, with its source. Low-confidence failure results at otherwise Safe scores display **Unknown / Reduced protection**, not Safe. Missing NLP/DOM scores are `null`. A URL failure uses clearly labeled local heuristics. The backend and extension share the same fallback predicates and category boundaries.
- Text shorter than 20 non-whitespace characters skips NLP; an empty page can still have URL+DOM analysis. Native LightGBM TreeSHAP explains positive raw-model contributions; heuristics and phrase/DOM explanations are labeled separately. NLP explanation sentence scores are model observations, not calibrated causal contributions.
- Backend: one service per app, thread-safe TTL/LRU, 512 entries, 24 hours, deep-copied values, input/model/config/policy-sensitive hashed keys. Model/tokenizer file metadata contribute to the revision. Restart after changing model files. Failed/incomplete explanations or detectors are not cached.
- Extension: URL-only cache separated from full per-tab results, maximum 100 URLs, 5 minutes, LRU. Forced rescans bypass both caches and collect current page text/DOM. Full results are validated against current tab URL and request generation. Degraded per-tab results expire after five seconds so an open popup retries full analysis after recovery. Settings changes clear caches. Service-worker restarts drop caches. Navigation invalidates previous results.
- Temporary bypasses are exact-URL matches for 30 minutes, at most 100 entries, stored in session storage. They survive service-worker restarts and clear on browser restart. Bypassed pages still receive full analysis and highlighting.
- API body limit 256 KiB; URLs 2,048 characters, text 100,000 characters, DOM 64 KiB, forms/inputs 100 each; batch 100 URLs. Analysis limit 120 work units/minute per process; each batch URL consumes a unit. Four detector threads and eight outstanding jobs bound work. Detector deadline 20 seconds; extension URL deadline 8 seconds and page deadline 25 seconds. Running native tasks cannot be forcibly canceled; queue capacity prevents unbounded accumulation. Use one local server process for these limits.

## Reproducible tests

```powershell
python -X utf8 -m pytest backend/tests -m 'not real_model' -q
python -X utf8 -m pytest backend/tests -m real_model -q
node --test tests/extension.test.cjs
```

The browser harness requires Playwright and a Chromium binary that still supports command-line unpacked extensions. Chrome for Testing 134.0.6998.165 was used in this environment; use that isolated binary only for these tests, not ordinary browsing. Installed Chrome/Edge releases may ignore sideload flags. Current compatible Playwright Chromium is preferable if it launches correctly on your machine.

```powershell
$env:PLAYWRIGHT_MODULE = 'ABSOLUTE_PATH_TO_NODE_MODULES/playwright'
$env:CHROME_PATH = 'ABSOLUTE_PATH_TO_CHROME_FOR_TESTING/chrome.exe'
$env:PYTHON = 'ABSOLUTE_PATH_TO_VENV/Scripts/python.exe'
node tests/e2e/browser.cjs
```

Ports 5057, 5058 and 8765 must be free. The harness launches/stops its own real backend, warms the saved models, generates ephemeral pairing credentials, creates an isolated browser profile in the OS temp directory, serves dummy local fixtures, and writes actual results/screenshots to `tests/e2e/artifacts`. Profiles and tokens are excluded from artifacts. Temporary profiles retain their ephemeral token on disk until removed by normal OS temporary-file cleanup.

The `fixture.github.com` hostname is mapped **inside the isolated test browser** to the local fixture server. It exercises the pre-existing trusted-domain cap to test a Safe UI path; it is **not evidence of model accuracy on arbitrary benign sites**. A separate genuine `localhost` false-positive test records the model limitation. The phishing hostname is likewise mapped locally. No live malicious site is visited and the forms submit no credentials. Malformed/timeout responses are restricted to separate fault-injection tests; successful detection assertions use the real Flask/model pipeline.

`webNavigation.onBeforeNavigate` is asynchronous notification, not synchronous network blocking. The content overlay and later warning redirect reduce exposure but cannot prevent a page from executing or transmitting before detection. This architecture is not a network firewall. See the completion report for actual test outcomes and unresolved model-quality limitations.
