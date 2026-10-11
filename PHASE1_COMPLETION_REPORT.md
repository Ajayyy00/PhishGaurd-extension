# PhishGuard Phase 1 — implementation and verification

## Scope and release status

All URL, NLP, DOM, combined scoring, explanation, popup, warning/bypass, highlighting, batch and fallback features remain available. The canceled module-hiding demo was not reapplied. Implementation was developed on `phase1-security-stability-testing`, based on upstream commit `14a443b3d684549a4cbcbd6dc65ac28c227a50c6`, and prepared for the user-requested GitHub publication on `phase1-security-reliability-2026-10-11`. No deployment was performed.

**Implementation and functional verification are finished: 65 backend tests and 7 extension unit tests passed; 16 real-browser checks were verified. Phase 1 is not fully accepted because benign-site accuracy fails.** The unchanged URL model incorrectly flags the benign localhost fixture. This is not a claim of production readiness or reliable classification of arbitrary websites. No scores or trained weights were altered to make a fixture pass.

## 1. Baseline and confirmed original issues

- The freshly restored checkout was clean before Phase 1. The original four API tests passed in 0.36 seconds, but only exercised a legacy heuristic application.
- `backend/run.py` imports `app`; Python resolved `backend/app/__init__.py`, silently bypassing the full factory in `backend/app.py`. The original server returned health 200, status `model_loaded: false`, and `/api/info` 404. An unauthenticated analysis from an arbitrary website origin returned 200 and risk 0 for `https://example.com`, even when text/DOM were supplied. The legacy path ignored the full pipeline's text field.
- Original startup bound to `0.0.0.0`, exposed a LAN address, and used development defaults. Full-factory CORS was wildcard; API routes lacked bearer authentication and work limits.
- Dynamic explanations were interpolated into warning/content/popup HTML. Warning targets accepted unvalidated query parameters. An inline image error handler conflicted with extension CSP.
- Categories and thresholds differed across components. Missing NLP/DOM values were treated as zero. URL-only results could be confused with full results; exceptions could become apparently Safe predictions.
- Analyzer creation per request defeated persistent service caching. The backend cache had no capacity bound; extension navigation/rescan handling could reuse stale results.
- The extension sent only DOM counts, so brand/form detectors lacked the actual title, text and field metadata. DOM domain matching accepted substring lookalikes; absolute same-site form actions were treated as external.
- NLP model weights were absent from the Git checkout. Only the missing `model.safetensors` was restored from the user's verified pre-reset backup after comparing configuration/tokenizer data. No model was trained or overwritten.
- Real Windows loading exposed CRLF corruption of LightGBM's internal tree offsets. The trained text file itself remains unchanged; loading now normalizes newlines in memory.
- The separate SHAP package failed on the reconstructed LightGBM booster (`objective` metadata) and incurred expensive initialization. LightGBM's built-in TreeSHAP preserves actual model explanations without that dependency path; additivity is tested against raw model output.

## 2. Changes by file

| Files | Problem solved and implementation |
|---|---|
| `backend/app.py`, `backend/app/__init__.py`, `backend/run.py` | Both entry points use the complete secured factory; loopback and production defaults; one analyzer per app; bounded request bodies and generic JSON errors. The compatibility loader avoids deleting the historical package. |
| `backend/config/settings.py`, `backend/.env.example` | Remove hardcoded secrets, document environment pairing and fail-closed defaults. |
| `backend/utils/security.py` | Constant-time bearer authentication, exact extension-origin policy, preflight validation, loopback Host validation, process-local work limiter, no-store/nosniff headers. |
| `backend/utils/validators.py` | Bounded URL/text/DOM/batch schemas; reject invalid schemes, ports, controls, malformed collections and non-finite DOM values. |
| `backend/routes/analyze.py`, `backend/routes/status.py` | Shared real analyzer, validated legacy field aliases, forced refresh, per-item batch error isolation, actual model/cache status, privacy-conscious logs. |
| `backend/services/risk.py`, `backend/services/cache.py` | Canonical score policy and thread-safe bounded TTL/LRU with copy isolation/statistics. |
| `backend/services/analyzer.py` | Input-sensitive cache keys; renormalized partial scores; explicit detector/source states; bounded inference pool/deadlines; visible failures; preserve explanation and phrase outputs. |
| `backend/services/url_detector.py` | Load unchanged Windows model safely; synchronized loading, strict failures, consistent public prediction policy, native TreeSHAP, canonical offline heuristics. |
| `backend/services/nlp_detector.py` | Local-only MiniLM loading, explicit missing/inference failure, serializable confidence and synchronized singleton initialization. Correct misleading TF-IDF documentation. |
| `backend/services/dom_detector.py` | Exact/subdomain host matching, same-site action handling, brand-specific matching bonus, remove the overly broad `pp` brand substring, synchronized singleton initialization. |
| `backend/requirements.txt` | Add the missing LightGBM dependency; preserve other dependencies. |
| `extension/shared/risk.js` | Matching classification/blocking boundaries, finite-score and HTTP URL validation, safe HTML escaping for the retained overlay layout. |
| `extension/background/background.js` | Authenticated loopback requests; token in extension-origin IndexedDB; trusted message checks; bounded caches; current-tab/request checks; serialized counters; time-limited session bypasses; explicit reduced protection and short-lived degraded results. |
| `extension/options/options.html`, `extension/options/options.js`, `extension/manifest.json` | User pairing/connection test, shared score script, options entry; warning page no longer exposed as a web-accessible resource. No token bundled in source. |
| `extension/content/content.js` | Escape untrusted overlay content; collect bounded visible text/title/forms/input metadata without credential values; require trusted user clicks for in-page bypass; retain highlights; rescan dynamic text; ignore self-generated mutations; stale-result checks; reduced-protection indicators. |
| `extension/popup/popup.js`, `extension/popup/popup.html`, `extension/popup/popup.css` | Render explanations as text; report stage/unavailable detectors; full-content rescans; current-tab checks; preserve toggles; remove external favicon/font requests and inline handler; constrain the local icon dimensions. |
| `extension/warning/warning.js`, `extension/warning/warning.html` | Validate target/score, construct reason nodes safely, show canonical categories and blocking-score basis; enforce successful bypass response; Go Back uses `about:blank` to avoid loops. |
| `backend/tests/*`, `pytest.ini`, `tests/extension.test.cjs`, `tests/e2e/*` | Deterministic tests, separate saved-model integration, real Chromium automation/fault injection, result logs and actual screenshots. |
| `README.md`, `docs/PHASE1_SETUP.md`, this report | Secure setup, reproducible tests, explicit policies and honest limitations. |

## 3. Security boundary

The extension and a local Flask process share a randomly generated private bearer token. It is never embedded in committed JavaScript. The options page stores it in IndexedDB on the extension's own origin; content-script IndexedDB belongs to the visited page's origin. Only trusted extension UI can change endpoint/token settings; settings replies omit the token. Recent browsers additionally restrict non-secret local-storage access when `setAccessLevel` exists. The first browser run exposed that API's absence in Chrome 134; this was fixed without falling back to storing the secret in content-accessible storage.

The server defaults to `127.0.0.1`, rejects non-loopback Host values and arbitrary supplied Origin values, and requires the token even when Origin is absent or approved. Public `/health` reveals liveness only. CORS is a browser boundary, not authentication. Tokens do not defend against a malicious program already running as the same OS user. Requests never fetch the supplied page URL; the browser provides text/DOM. Model loading is local only.

Limits: 256 KiB request body; 2,048-character URLs; 100,000-character text; 64 KiB DOM; 100 form/input records; 100 URLs per batch; 120 analysis units/minute per server process. Each batch item consumes a unit. Unauthorized requests cannot consume model work. API failures return generic messages rather than stack traces. Logs avoid scanned URLs, page text and tokens.

Warning/popup reasons use `textContent`; the retained content overlay escapes all interpolated URL/explanation strings and validates numeric/category fields. Highlighted page text is inserted as text nodes. Malicious HTML/query-parameter regression checks inspect all three renderers in the real browser. In-page Proceed/Back handlers are scoped to the overlay and require browser-trusted click events, preventing visited-page JavaScript from granting itself a bypass with `.click()`. The shared-DOM limitation still applies.

## 4. Scoring contract

For available detector values, `final = floor(sum(weight × score) / sum(available weights))`. Full weights: URL 30, NLP 40, DOM 30. URL-only = URL 100%; URL+NLP = 30/70 and 40/70; URL+DOM = 50/50. Missing detectors are `null`, never fabricated zeros. Status records distinguish `ok`, `not_run`, `failed`, `timed_out` and identify a model, similarity or heuristic-fallback source. Text shorter than 20 trimmed characters skips NLP.

Safe `<=30`; Suspicious `>30` through `70`; Dangerous `>70`. A degraded result that would otherwise be Safe is **Unknown**, with reduced protection. Unknown is an availability state, not an extra risk band. URL `>=90` preserves the original final-score floor of 90. The original precautionary URL block threshold `>=50` remains; a full combined score `>70` now also triggers the intended warning. Warning pages label URL versus combined protection score when these differ.

The URL model's existing trusted-domain/TLD/OAuth adjustments are retained. MiniLM's existing model/phrase/keyword blend is retained. Native TreeSHAP values explain raw URL-model contributions; heuristic and DOM/NLP explanations remain separate. These scores are not calibrated probabilities; fabricated overall confidence values were removed.

## 5. Caching and reliability

Backend cache: one service per app, 512 entries, 24-hour TTL, true LRU, locks, deep copies and counters. Keys hash URL/text/DOM, policy, timeout configuration and model/tokenizer file revision metadata; URL-only and full inputs cannot collide. Model changes require process restart. Failed detector/explanation results are not cached.

Extension cache: 100 URL-only entries, 5-minute TTL/LRU, distinct full per-tab results; forced rescans bypass both layers. Tab URL/request generations prevent stale responses replacing another page. Degraded per-tab results expire after five seconds so an open popup retries. Settings changes clear caches; service-worker restarts rebuild empty caches. Bypasses are exact-URL, 30-minute, capped at 100, survive worker restarts and clear on browser restart.

Four inference threads/eight outstanding jobs and a 20-second detector deadline bound work. Extension URL/page deadlines are 8/25 seconds. Running native inference cannot be forcibly killed; timed-out jobs remain bounded until they return. Batch failures are isolated per item. Model singleton initialization and cache/statistics mutations are synchronized.

## 6. Executed tests

- Original baseline: **4 passed** (legacy API only).
- Actual `python backend/run.py` subprocess smoke check: health 200, unauthenticated status 401, authenticated info 200, unauthorized Origin 403; debug off and loopback binding. See `entrypoint-smoke.json` and `entrypoint-smoke.log`.
- `python -X utf8 -m pytest backend/tests -q --junitxml=tests/e2e/artifacts/all-backend-results.xml`: **65 passed** in the latest backend run, including the separate saved-model test.
- `node --test tests/extension.test.cjs`: **7 passed**. These are deterministic unit doubles, not browser evidence.
- Real saved-artifact checks execute 22-feature LightGBM prediction, native TreeSHAP/additivity, MiniLM tokenization/inference/phrase extraction, DOM matching, all-stage orchestration and actual authenticated Flask endpoints. No trained detector is mocked in this integration test.
- Deterministic checks cover category boundaries, invalid numbers, partial weights, cache TTL/LRU/copy isolation/concurrency, malformed payloads, auth/CORS/Host/size/rate limits, failures/timeouts/capacity, batch continuation and singleton races.
- All 13 recorded model/training files compare byte-for-byte with the start-of-phase hashes. See `protected-files-before.json` and `protected-files-after.json`. This includes the restored, previously missing NLP weights.
- Tested environment: Python 3.11, Flask 3.0.0, LightGBM 4.6.0, transformers 4.37.0, torch 2.5.1+cu121, NumPy 1.26.3, pandas 2.1.4, pytest 7.4.4. The installed torch version differs from the older requirements pin; a fresh dependency installation was not certified.

## 7. Actual browser evidence

Chrome for Testing **134.0.6998.165**, headless, persistent isolated temporary profile. The real unpacked MV3 worker starts at `chrome-extension://mihecjaodbnkcoooajmdniinndogined/background/background.js`. A real Flask subprocess runs throughout each E2E session, except the explicit stop/recovery test. Pairing uses the actual options UI and random in-memory credentials. No simulation substitutes for the successful detection pipeline.

`chrome.action.openPopup` creates a real action popup target. Playwright did not expose it as a normal Page, so the harness attaches with Chrome DevTools Protocol, reads its actual DOM, dispatches mouse events and captures its actual surface. It does not replace the popup's detection results. Browser and service-worker restarts use the same isolated profile as appropriate.

Local fixtures cover benign content, a dummy PayPal/urgent-verification simulation, dynamic text, empty/long content, redirects, rapid navigation and edge URLs. The test browser alone maps `fixture.github.com` and the simulated phishing hostname to loopback. The trusted-domain fixture tests the existing Safe UI path; it is not independent evidence of model accuracy. A separate `localhost` fixture records its genuine false positive. A public Wikipedia visit is an additional observation, not the deterministic pass/fail dependency.

The final `node tests/e2e/browser.cjs` run finished at **2026-10-10 15:52:25 UTC (21:22:25 IST)** after the final code changes: **16 VERIFIED, 0 FAILED**, with no fatal harness error. These include a check that successfully records a model false positive; they do not mean the benign-site accuracy criterion passed.

| Executed browser check | Result |
|---|---|
| Actual MV3 worker, options pairing and authenticated Flask connection | VERIFIED |
| Locally mapped trusted-host benign page: URL-only to full analysis | VERIFIED |
| Benign localhost false-positive measurement | VERIFIED measurement; accuracy FAILED |
| Dangerous URL warning, model reasons and Go Back | VERIFIED |
| Proceed Anyway, temporary bypass and real NLP/DOM analysis | VERIFIED |
| Native popup, current URL, gauge/bars, rescan, toggle and reopen | VERIFIED |
| Dynamic text highlighting, no nested duplicates, observer settles, page interaction | VERIFIED |
| XSS in warning/popup/content, invalid warning target, scripted bypass rejection and token isolation | VERIFIED |
| Multiple tabs, rapid navigation, redirect and reload | VERIFIED |
| Empty/long content, encoded characters, Unicode hostname and overlong URL | VERIFIED |
| Malformed API response and real network timeout, visible degradation and recovery | VERIFIED |
| Actual Flask stop, safe/suspicious fallback, restart and full-analysis recovery | VERIFIED |
| Service-worker stop/restart retains pairing and session bypass | VERIFIED |
| Browser restart retains pairing and clears temporary bypass | VERIFIED |
| Ordinary public Wikipedia visit | VERIFIED navigation/URL-only observation; no full-page accuracy claim |
| No uncaught page or worker JavaScript exceptions | VERIFIED |

Measured benign trusted-host scores were URL **25**, NLP **2**, DOM **0**, combined **8**. The local phishing simulation returned URL **100**, NLP **76**, DOM **93**, combined **90** (the preserved high-URL floor applies). Benign localhost returned URL **100** and was incorrectly blocked. The console also retained one handled `Analysis error: Error: Untrusted context` diagnostic; the empty uncaught-error lists are not a claim that every console message was error-free.

Authoritative evidence: [browser JSON](tests/e2e/artifacts/browser-results.json), [custom browser HTML report](tests/e2e/artifacts/browser-report.html), `tests/e2e/artifacts/backend-browser.log`, [backend XML](tests/e2e/artifacts/all-backend-results.xml), and [extension TAP](tests/e2e/artifacts/extension-unit-results.txt). The HTML report is produced by the Playwright-driven custom harness, not the Playwright Test reporter. Earlier failed runs are retained separately to expose regressions and harness corrections.

Actual execution screenshots: [safe analysis](tests/e2e/artifacts/safe-analysis.png), [phishing analysis](tests/e2e/artifacts/suspicious-analysis.png), [warning page](tests/e2e/artifacts/warning-page.png), [native popup](tests/e2e/artifacts/popup-dashboard.png), [dynamic highlights](tests/e2e/artifacts/dynamic-highlights.png), [offline popup](tests/e2e/artifacts/offline-popup.png), and [offline warning](tests/e2e/artifacts/offline-warning.png).

## 8. Remaining limitations and acceptance gaps

1. **FAILED benign-site accuracy acceptance:** the trained URL detector assigns the benign `http://localhost:8765/benign` score 100 and redirects to a warning. The existing trusted-domain cap makes the locally resolved trusted-domain fixture Safe. This distinction is explicit; broad accuracy/false-positive-rate evaluation and model calibration/retraining were not performed. The allowlist and model weights were not weakened or changed to pass tests.
2. **Asynchronous protection:** MV3 `onBeforeNavigate` does not synchronously block requests. Page requests/scripts can execute before the overlay or redirect. A hostile page can manipulate the shared DOM. This is not a firewall or a guaranteed credential-exfiltration barrier.
3. The Git checkout alone does not include MiniLM weights. This workspace has a verified restored artifact; other machines must provision it separately. No unknown model download is attempted.
4. Native detector tasks cannot be interrupted forcibly. Bounded capacity/timeouts prevent unbounded queue growth but cannot guarantee recovery from a permanently hung native library without restarting the server.
5. Caches/limiter are process-local; this is a single-user loopback service, not a multi-process internet deployment. Local malware can access a same-user profile/token.
6. Chrome 134 was isolated for compatibility testing. Installed newer Chrome's CLI sideload restrictions and the environment's bundled Chromium launch failures are not application successes. Modern Chrome manual installation, fresh pinned-dependency installation, other OSes, large-scale accuracy/load tests and true pre-network blocking remain **NOT TESTED** or outside this phase.
7. Legacy `backend/app/routes.py` remains as unregistered historical code. Both supported entry points now use the secured full pipeline; do not register the legacy blueprint in another server.

## 9. Final verification

| Required component | Status | Executed evidence and scope |
|---|---|---|
| Flask backend | VERIFIED | Actual production-default entry point smoke, authenticated API integration and real browser subprocess. |
| LightGBM URL detector | VERIFIED functionality; accuracy gap | Saved-model prediction, 22-feature extraction, TreeSHAP additivity and real navigation. Benign localhost false positive remains. |
| MiniLM NLP detector | VERIFIED | Local saved weights, tokenization/inference, suspicious phrases and real full-page requests. |
| DOM similarity detector | VERIFIED | Exact-host/form regression tests and local brand-impersonation fixture. |
| Combined scoring | VERIFIED | Partial/full weights, boundary tests, missing/failure states and matching browser scores. |
| Chrome extension | VERIFIED | Actual unpacked MV3 extension on Chrome for Testing 134, navigation and lifecycle checks. |
| Popup dashboard | VERIFIED | Native action popup inspected and clicked through CDP; gauge, bars, rescan, settings and reopening. |
| Warning page | VERIFIED | Actual redirects, safe text rendering, Go Back, Proceed Anyway and bypass expiry/lifecycle. |
| In-page highlighting | VERIFIED | Real dynamic page, phrase spans, toggles, duplicate/observer and interaction checks. |
| API security | VERIFIED within tested boundary | Token, Origin/CORS, Host, body/schema/rate limits, extension secret isolation and XSS regressions. Not a penetration-test certification. |
| Offline fallback | VERIFIED | Actual backend stop/restart plus timeout/malformed-response fault injection; reduced protection visible. |
| Automated tests | VERIFIED | 65 backend tests and 7 extension unit tests passed, zero skipped in those final runs. |
| Real-browser E2E tests | VERIFIED execution | 16 checks verified on actual Chrome; false-positive measurement is not an accuracy pass. |
| Safe websites are not incorrectly blocked | FAILED | Benign localhost scored 100 and triggered a warning. |
| Fresh pinned install / modern installed Chrome / other OSes | NOT TESTED | Environment and browser-version limits above apply. |

All existing modules remain active. Model/training artifacts were preserved. No deployment was performed. Test XML machine hostnames were redacted for repository publication; test outcomes are unchanged. **Do not treat this phase as fully accepted or production-ready until the false-positive issue is resolved and the relevant acceptance checks pass.**

## References and reproduction

See [secure setup and commands](docs/PHASE1_SETUP.md). Browser mechanics were checked against [Playwright extension testing](https://playwright.dev/docs/chrome-extensions), [Chrome extension storage](https://developer.chrome.com/docs/extensions/reference/api/storage), and [Chrome's CLI sideload announcement](https://groups.google.com/a/chromium.org/g/chromium-extensions/c/1-g8EFx2BBY/m/S0ET5wPjCAAJ). The browser harness uses Chrome for Testing, whose sideload support is distinct from branded Chrome.
