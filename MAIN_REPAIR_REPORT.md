# Main-branch repair and browser verification

Date: **27 October 2026**. Checkout: `D:\scam_extension\phishguard-main-verification`. Branch: **`fix/main-e2e-verification`**, created from `14a443b3d684549a4cbcbd6dc65ac28c227a50c6`.

The eleven integration, loading, contract, cache, security, highlighting and lifecycle issues in the prior report have been repaired. The normal `python backend/run.py` entry point now initializes the real LightGBM and MiniLM models and serves the complete authenticated URL/NLP/DOM pipeline. All original features remain active. The sibling Phase 1 checkout was not changed.

**Functional verification passes. This does not establish general model accuracy:** the unchanged URL model still falsely flags benign localhost. That limitation is recorded separately below, rather than hidden by the passing UI tests. No training or learned-weight changes were made. Nothing was committed or pushed in this task.

## Final executed test results

| Verification | Result | Evidence |
|---|---|---|
| Original pytest suite, unchanged test bodies | **4/4 passed** | Original command executed; these four cases also appear in the combined XML. |
| Original suite plus new real-model/API regressions | **22/22 passed** | [backend-results.xml](tests/e2e/artifacts/backend-results.xml) |
| Extension unit tests | **7/7 passed** | [extension-unit-results.txt](tests/e2e/artifacts/extension-unit-results.txt) |
| Default-path model probes: URL/SHAP, MiniLM, DOM, full factory, cache transition | **5/5 VERIFIED** | [model-probe-summary.json](tests/e2e/artifacts/model-probe-summary.json) |
| Real Chrome extension, headless functional run | **25/25 VERIFIED** | [headless/browser-results.json](tests/e2e/artifacts/headless/browser-results.json) |
| Final real Chrome extension, visible window, including computed visual checks | **25/25 VERIFIED, 0 FAILED** | [browser-results.json](tests/e2e/artifacts/browser-results.json), [HTML evidence](tests/e2e/artifacts/browser-report.html) |

Browser: **Chrome for Testing 134.0.6998.165 on Windows**, actual unpacked Manifest V3 extension, isolated persistent profile. The final run used a visible browser window. The native action popup was opened with `chrome.action.openPopup`, operated with CDP mouse events, and inspected for text, actual CSS colors, gauge geometry and rendered progress-bar widths. No successful analysis responses were mocked. All browser tests started the actual `backend/run.py` subprocess and paired through the actual options screen.

The final browser run recorded zero uncaught page errors and zero worker errors. The harness actually stopped Flask to test fallback, restarted it to test recovery, and stopped/restarted the service worker to test bypass persistence. Test browser/server processes were stopped afterward.

## Measured behavior

- Initial phishing URL: model/API and warning score **100**, matching without the former 55-to-0 response-field loss.
- After the real Proceed Anyway click, the local phishing simulation produced URL **100**, MiniLM **76**, DOM **91**, final **90**, with a **Dangerous** badge and actual model explanations. The preserved URL-at-least-90 floor applies to the weighted score.
- The final popup screenshot visibly shows a red 90/100 gauge, red Dangerous badge, and bars at 100%, 76% and 91%: [native popup](tests/e2e/artifacts/native-popup.png).
- URL-only cache probe: URL **49**, final **49**, NLP/DOM **null** with `not_run` status. Adding text and DOM for the same URL gives a separate full result, final **73**. Repeating the full input returns `cached: true`; forcing a refresh returns `cached: false`. See [cache.json](tests/e2e/artifacts/cache.json).
- Default-path LightGBM loads with real TreeSHAP; default-path MiniLM loads its restored trained weights; the standalone DOM fixture scores **93**. The standalone fixture has three inputs, whereas the browser fixture has two, so its DOM score differs legitimately.

## Repairs by issue

1. **Startup shadowing:** the `backend/app/` compatibility package delegates to the full factory. Both normal entry points use the complete API. The factory initializes detectors before accepting requests; authenticated status reports their actual readiness and `/api/info` works.
2. **Windows model crash:** restored the model file to the exact original Git blob bytes; `.gitattributes` forces LF. The loader additionally normalizes newlines in memory and constructs the native booster from the normalized string. A regression loads a deliberately CRLF-encoded temporary copy and verifies TreeSHAP additivity.
3. **Missing MiniLM weights:** copied the existing trained `model.safetensors` into this checkout's default artifact directory. Loading is local-only. The weight SHA-256 is unchanged; see [model-integrity.json](tests/e2e/artifacts/model-integrity.json).
4. **Request/response mismatch:** the API accepts `text`/`content`, `dom`/`dom_fingerprint`, legacy top-level `forms`, and `force_refresh`/`rescan`. Form flags feed real DOM features. Responses include `final_score`, `risk_score`, detector scores, `explanations`, string `reasons`, status/stage metadata, and the legacy `is_phishing` key. Validation applies to both schemas.
5. **Partial scoring and cache:** available detectors are weighted and renormalized; missing detectors are never zero votes. Keys include URL, text, DOM, model revision, policy and inference configuration. The shared backend cache is bounded, thread-safe, TTL/LRU, and supports forced refresh. Frontend URL and full-page caches are distinct.
6. **Authentication and validation:** bearer authentication and exact extension origins are required for API access. No token is hardcoded. Pairing uses private extension-origin IndexedDB; settings replies omit the token. Loopback binding, Host checks, bounded inputs, rate limits and generic errors remain enforced in production and testing. Authenticated invalid schemes return 400; unauthenticated analysis returns 401.
7. **Rescan:** the popup requests current page extraction, sending actual visible text, title, inputs, forms and `force_refresh: true`. Browser assertions inspect the new network request; a cached URL-only response cannot satisfy this check.
8. **Short dynamic phrases:** the observer handles newly inserted short text and character changes with debounce, ignores extension-owned mutations, avoids nested highlights, and updates the displayed highlight count.
9. **HTML injection:** warning and popup explanations use text nodes. The retained in-page overlay layout escapes all interpolated untrusted content. Browser checks require literal `<b>` text and absence of an injected element. In-page bypass clicks also require trusted user events.
10. **Bypass lifecycle:** timestamped, exact-URL 30-minute bypasses live in `chrome.storage.session`, survive real worker restarts, and are bounded. Browser-session termination clears them. Bypassed pages still receive full text/DOM analysis.
11. **Full-service cache transition:** the formerly identical URL-only/full cached object is no longer reused across input stages. The default-path cache probe and API regression verify fresh NLP/DOM execution and correct scores for the same URL.

During screenshot review, an additional popup bug was found: CSS still styled the old `warning`/`danger` names instead of the canonical `suspicious`/`dangerous` names. The selectors now cover the canonical names, and the initial analyzing state is neutral. Final browser checks wait for animation completion and assert actual red badge/gauge colors and proportional bar geometry. Earlier pre-fix evidence is retained in `tests/e2e/artifacts/before-visual-fix/`; it is not the final visual result.

## Scoring and operation

Full weights remain URL 30%, NLP 40%, DOM 30%; partial results divide by the sum of available weights. Integer truncation is preserved. Safe is 0–30, Suspicious is greater than 30 through 70, Dangerous is greater than 70. A failed/degraded otherwise-Safe result is Unknown. URL risk at least 50 preserves the precautionary URL warning; full combined risk greater than 70 also warns. URL risk at least 90 preserves the final-score floor of 90. Warning pages label the score's URL/combined basis.

Backend cache: 512 entries, 24-hour TTL. Extension URL cache: 100 entries, five-minute TTL. Request generations and current-tab checks prevent stale navigation results from replacing a new page. Offline or failed detection is labeled Reduced protection; an open popup retries stale degraded results. Input/body/rate bounds and inference queue/deadline bounds prevent unlimited work. Native inference already running cannot be forcibly interrupted.

## Test integrity and historical-harness incompatibilities

The historical scripts and their failures at `D:\scam_extension\main-verification-2026-10-24` were **not modified**. The new reproducible scripts live under this checkout's `tests/e2e/`.

The old harness cannot literally satisfy all its assertions with authentication enabled: it uses unauthenticated requests for successful API tests, then requires that same recorded response to have status 401. It also expects to inspect the phishing page after requiring a warning redirect, without clicking Proceed. The repaired harness separates real authenticated and unauthenticated calls, compares the same analysis stage, and follows the actual warning/Proceed lifecycle. It verifies the repaired local Go Back destination and explicit reduced-protection label. No check was made to pass by weakening application security or supplying fabricated detector results.

The original `backend/tests/` files and assertions remain unchanged. Root `conftest.py` supplies a random bearer credential to their test transport, just as a paired extension does. It does **not** bypass authorization or replace models. New tests explicitly prove unauthenticated requests return 401 even in testing mode.

The benign UI fixture uses `fixture.github.com` resolved to the local server only inside the isolated test browser, exercising the existing trusted-domain policy. This is a setup change from the old localhost fixture, not proof that localhost accuracy improved. A separate real localhost model result is saved in every browser run. See [HARNESS_NOTES.md](tests/e2e/HARNESS_NOTES.md) for all setup/expectation changes.

## Modified and added files

| File | Change |
|---|---|
| `.gitattributes` | LF model text and binary weight handling. |
| `README.md` | Correct startup links, model description, no unnecessary npm step or production-readiness claim. |
| `backend/.env.example` | Safe environment pairing reference. |
| `backend/app.py` | Secured full factory, default model initialization, shared analyzer and generic errors. |
| `backend/app/__init__.py` | Route imports to the full factory. |
| `backend/config/settings.py` | Remove hardcoded configuration secret. |
| `backend/requirements.txt` | Declare required LightGBM dependency. |
| `backend/routes/analyze.py` | Legacy/current schemas, shared analyzer, fresh rescans and batch failure isolation. |
| `backend/routes/status.py` | Actual detector readiness and shared-cache status. |
| `backend/run.py` | Full factory, loopback, production default. |
| `backend/services/analyzer.py` | Active-detector scoring, response aliases, bounded inference, stage-sensitive cache and visible failures. |
| `backend/services/cache.py` | Thread-safe bounded TTL/LRU cache. |
| `backend/services/risk.py` | Shared score/threshold contract. |
| `backend/services/url_detector.py` | CRLF-safe loading, real native TreeSHAP adapter, synchronized singleton/model access and explicit failures. |
| `backend/services/nlp_detector.py` | Local MiniLM loading, serializable outputs, missing-model states and synchronized initialization. |
| `backend/services/dom_detector.py` | Exact/subdomain matching, own/external form handling, brand-specific matching and legacy form flags. |
| `backend/utils/security.py` | Authentication, CORS/Host checks, work limits and response headers. |
| `backend/utils/validators.py` | Bounded, typed URL/text/DOM/batch validation and legacy/rescan aliases. |
| `extension/background/background.js` | Pairing, accurate result normalization, bounded separate caches, stale-response protection and persisted bypasses. |
| `extension/content/content.js` | Fresh page extraction/rescan, safe overlay, short dynamic highlighting, observer stability and reduced-protection states. |
| `extension/manifest.json` | Shared risk script, connection options, restricted warning-resource exposure. |
| `extension/options/options.html` | Pairing/settings UI. |
| `extension/options/options.js` | Save credentials privately and test the actual authenticated connection. |
| `extension/shared/risk.js` | Canonical frontend score categories, validation and HTML escaping. |
| `extension/popup/popup.js` | Full rescans, accurate scores and unavailable states, safe explanations and current-tab checks. |
| `extension/popup/popup.html` | Connection/stage display, local assets, neutral analyzing state. |
| `extension/popup/popup.css` | Canonical badge colors, constrained favicon and URL layout. |
| `extension/warning/warning.js` | Safe reason nodes, validated targets/scores, successful bypass gating and local safe destination. |
| `extension/warning/warning.html` | Shared risk contract and labeled protection-score basis. |
| `conftest.py` | Authenticated test transport for unchanged original tests. |
| `tests/test_main_repair.py` | Real API/model, auth, alias, validation, cache and CRLF/TreeSHAP regressions. |
| `tests/extension.test.cjs` | Seven deterministic worker/risk/security unit tests; distinct from browser proof. |
| `tests/e2e/probe_models.py` | Five asserting default-path real-model probes. |
| `tests/e2e/verify-browser.cjs` | 25 actual API/browser checks with native-popup visual assertions. |
| `tests/e2e/HARNESS_NOTES.md` | Transparent differences from historical diagnostic setup. |
| `docs/MAIN_REPAIR_SETUP.md` | Startup, pairing, artifact provisioning and reproduction commands. |
| `MAIN_REPAIR_REPORT.md` | This report. |
| `models/saved/lgbm_url_model.txt` | Physical Windows checkout normalized to exact original LF Git blob; no learned values changed. |
| `models/saved/nlp_phish_model/model.safetensors` | Missing local artifact restored with original SHA-256; remains ignored by Git. |
| `tests/e2e/artifacts/*` | Actual results, logs, hashes, screenshots and earlier-run evidence. [Artifact manifest](tests/e2e/artifacts/artifact-manifest.json) enumerates generated files. |

No dataset, training script, or original backend test was edited. [Model integrity evidence](tests/e2e/artifacts/model-integrity.json) records the unchanged learned artifacts.

## Evidence and remaining limits

Screenshots: [online warning](tests/e2e/artifacts/online-warning.png), [native popup](tests/e2e/artifacts/native-popup.png), [safe page](tests/e2e/artifacts/safe-page.png), [dynamic highlights](tests/e2e/artifacts/dynamic-highlights.png), [literal HTML reasons](tests/e2e/artifacts/warning-inert-html.png), [offline warning](tests/e2e/artifacts/offline-warning.png), [offline popup](tests/e2e/artifacts/offline-popup.png).

- **Known model false positive remains:** benign `http://localhost:8766/benign` receives URL score 100. No allowlist/weight change was made to conceal it. The 25 passing checks establish repaired functionality, not a generally accurate classifier or production readiness.
- The initial webNavigation event is asynchronous; page requests/scripts may run before a warning. This is not guaranteed pre-network blocking.
- The restored MiniLM weight file is intentionally Git-ignored. Fresh clones need that artifact provisioned separately. This workspace's normal startup was verified without alternate model paths.
- Verification used Chrome for Testing 134, both headless and visible. A different installed Chrome build, other operating systems, a fresh pinned-dependency install and broad accuracy/load benchmarks were not certified.
- The test forms contain dummy content and do not submit credentials. The browser's local hostname mapping and unrelated-resource blocking are test setup only; ordinary browser DNS and user profiles were not modified.
- The pairing configuration must be supplied before protected API use. No token was embedded in source or included in captured artifacts. Limits and caches are process-local for this single-user local service.

See [setup and reproduction commands](docs/MAIN_REPAIR_SETUP.md). The current work is local on `fix/main-e2e-verification`; no push or deployment was requested or performed.
