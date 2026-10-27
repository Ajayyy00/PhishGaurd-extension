# PhishGuard targeted fixes — 27 October 2026

Changes are saved in `D:\scam_extension\phishguard-main-verification`, branch `fix/main-e2e-verification`. Existing unrelated repairs were preserved. No commit or push was made.

## Outcome

**Both browser feature failures are fixed, all three original false positives are corrected, and all six original false negatives now block.** The requested feature suite is **32/32 passing**. However, **zero detection regressions is not achieved**: the public Safe Browsing demonstration page (#32), previously blocked by the saturated URL model, is now unblocked under the new corroboration policy. It remains a false negative in this report; its label and fixture were not changed.

| Metric | Original audit | Updated run |
|---|---:|---:|
| Pages attempted | 44 | 44 |
| Usable / inconclusive | 39 / 5 | 39 / 5 |
| TP | 13 | 18 |
| FP | 3 | 0 |
| TN | 17 | 20 |
| FN | 6 | 1 |
| Precision | 81.25% | 100.00% |
| Recall | 68.42% | 94.74% |

These figures apply to this deliberately constructed test set: 19 live page attempts and 25 controlled simulations. They are not a general accuracy estimate. Positive means an actual blocking warning/overlay, rather than an amber indicator or nonzero score. The same five cases are inconclusive: Stack Overflow and npm challenges, Google Accounts without a usable full result, Amazon sign-in HTTP 404, and the credential-bearing @ URL without a usable full page. No exclusions were added to improve the result.

Mean navigation-to-final worker result: **1,480 ms**, including navigation and automated Proceed for blocked pages, excluding the harness's observation delay.

## Changes implemented

### Highlight state and startup

- Preferences start pending (`null`); the content script immediately calls the existing trusted worker bridge, which reads `chrome.storage.local`. Direct storage remains restricted to trusted extension contexts; token/storage protections were not weakened.
- Early analysis payloads wait for settings. Disabled highlighting explicitly removes existing marks. Highlight OFF persisted with **zero marks on all three reloads**.
- Automatic highlights are suppressed when the full verdict has final score <45 and DOM risk <40. The original MDN/GitHub educational fixtures no longer get their prior keyword-highlight noise.
- Full extraction starts at DOMContentLoaded after the URL check, with a debounced load/mutation update. A separate held-image test verified full analysis while `document.readyState` was still `interactive`; it did not wait for the load event.

### Privacy and long content

- Extraction includes bounded input, textarea and contenteditable descriptors: tag/type/name/id/placeholder/label. It never reads their typed values. A real-browser rescan with dummy secrets in all three surface types verified that none entered the payload.
- Text selection includes title/headings, form/control surroundings, the page head and the page tail within 10,000 characters. Case #43's late lure now appears in the captured request and the page blocks.
- MiniLM runs bounded head and tail windows for long inputs and takes the maximum phishing probability. Probability >=0.85 floors NLP risk at 75, preserving the seed-drainer model signal.
- This is not a universal cure for context dilution: a separate long benign-prefix diagnostic still produced NLP 30 despite two windows. The actual #43 fixture scored NLP 66 and blocked because its credential/DOM evidence corroborated it. Model accuracy still needs independent training/calibration work.

### DOM and URL evidence

- Generic same-site login forms score 30 rather than being assigned a random brand template and 86–90 risk. GitHub and ordinary member/OAuth login cases are unblocked.
- High DOM scores require stronger evidence: primary brand claim with credentials on an untrusted host, external credential submission, a seed/recovery-phrase surface, or urgent credential harvesting. Seed requests score 95. Ordinary account recovery codes are not treated as wallet seed phrases. Explanations name those observed signals rather than claiming an unsupported template match.
- Brand matching uses primary title/headings/asset metadata and credential labels, rather than incidental Google/Apple social-login mentions in page prose. Nearby unassociated labels are also captured without reading typed values. The first verification pass found the social-login issue and it was corrected before the final matrix.
- Removed `.org` and OAuth-query score discounts. Domain caps now match an exact named host or its `www` host; they no longer trust every descendant subdomain.
- The booster feature-name order exactly matches all 22 inference features. Added a load-time guard against future schema mismatch. Training code uses the same unscaled feature definitions.
- Found and fixed one actual batch/single discrepancy: pandas NaN ports were treated as nonstandard ports in batch training extraction. Batch/single features now match exactly. **The saved model has zero splits on `has_port`, so this discrepancy does not explain or fix its current saturation.**
- Native probabilities remain approximately 0.999 on the tested benign URLs. No model weights were changed or retrained. Native SHAP still satisfies additivity (maximum error about 1.3e-14).

### Scoring and extension agreement

- Policy version is `evidence-v2`. Full-page URL contribution is bounded when there is no hard URL indicator and DOM risk is low. A saturated URL prediction alone no longer causes an automatic redirect on every ordinary hostname.
- Corroborated DOM >=80 plus NLP >=50, or primary-brand credential impersonation, yields final score at least 90. Strong direct account threats/deadlines plus NLP >=75 yield at least 75 even without a form. Hard URL indicators retain precautionary protection.
- Online extension blocking now honors the authenticated backend's explicit boolean `should_block`; it no longer recomputes the old URL >=50 rule and defeats the fix. Offline heuristic blocking remains available.
- Both `/api/status` and `/api/info` report version 1.1.0. New cache keys include the updated policy version.
- The repaired checkout already contained the popup CSS/HTML correction. Loading that directory made the native popup badge, gauge and bars correctly red at score 90.

## Verification

| Check | Result |
|---|---|
| Original backend tests + prior repair tests + targeted regressions | **40/40 pass** |
| Extension unit tests | **7/7 pass** |
| `feature-audit.cjs` | **25/25 pass** |
| `supplement.cjs` | **7/7 pass** |
| `highlight-repro.cjs` | **3 reloads: stored false, 0 marks**; both harness checks pass |
| Extra browser privacy / slow-resource / late-lure checks | **3/3 pass**, plus pairing smoke check |
| Full matrix + harder matrix | **44 attempted, 39 usable**; metrics above |
| Final saved DOM/policy replay of captured browser results | **42/42 scores match**, including challenge pages with full results |
| JavaScript syntax and Git whitespace checks | Pass |
| Trained artifact hashes | Unchanged from audit |

The final saved-source replay covers narrow follow-up edits after the matrix backend started: preventing ordinary recovery codes from matching the seed pattern, narrowing trusted-domain explanation text, and considering credential labels as brand claims. It verifies final DOM scores and aggregation on captured data; it is not presented as a fresh transformer/browser run. The full feature suite was rerun after the label extraction change, and the focused browser privacy test verifies adjacent labels without a `for` association. Subsequent backend explanation wording and strong-DOM blocking when NLP is unavailable are covered by the final 40-test backend suite; they do not change these full-pipeline matrix outcomes.

The old audit scripts and results remain intact in `D:\scam_extension\audit-2026-10-27`. Copies here use the repaired extension and an isolated port-5010 backend. Feature copies start/stop their own backends. The sole behavioral fixture setup adjustment grants an explicit temporary bypass before inserting phishing text in the dynamic-highlighting test, because the stronger policy correctly redirects that page otherwise. Highlight assertions, popup assertions, website labels, and expected classification outcomes were not relaxed. A first attempt retained the old extension path due to Windows escaping; it was discarded and rerun with the verified repaired path.

## Remaining failure: public demonstration page

Case #32 is `https://testsafebrowsing.appspot.com/s/phishing.html`. It presents explanatory phishing/social-engineering text, generic username/password controls, no form action, and no claimed target brand. The final pipeline returns URL 99, NLP 9, DOM 30, final 21, no block. The previous block came from URL saturation, not robust recognition of the page's test designation.

The requested lower-risk treatment for generic login forms and uncorroborated URL scores removes that accidental protection. Inspecting the public page's HTML confirmed that its deceptive update/ad examples are images, which the current text/DOM pipeline does not interpret. A defensible next step is URL reputation integration or separately validated image/context detection, evaluated beyond these fixtures. No special-case block rule for this benchmark URL was added. **Do not report this run as zero regressions or as production-ready model calibration.**

Google Accounts also remains inconclusive in this isolated browser; local delayed-resource extraction is verified, but no successful full-page result is claimed for that live account page.

## Complete comparison

Scores are URL / NLP / DOM / final. `—` indicates no detector result. TP/TN/FP/FN measure blocking. IC is inconclusive.

| # | Case | Before | After | Updated scores | Blocked | Highlights |
|---:|---|---|---|---|---|---:|
| 1 | Google | TN | TN | 10 / 75 / 0 / 33 | No | 0 |
| 2 | GitHub | TN | TN | 10 / 41 / 30 / 28 | No | 0 |
| 3 | Wikipedia | TN | TN | 10 / 75 / 0 / 33 | No | 0 |
| 4 | Stack Overflow | IC | IC | 10 / 75 / 0 / 33 | No | 0 |
| 5 | Python | TN | TN | 99 / 5 / 0 / 11 | No | 0 |
| 6 | MDN | TN | TN | 99 / 6 / 0 / 11 | No | 0 |
| 7 | Cloudflare | FP | TN | 99 / 75 / 0 / 39 | No | 0 |
| 8 | Microsoft | TN | TN | 10 / 75 / 0 / 33 | No | 0 |
| 9 | npm | IC | IC | 99 / 75 / 0 / 39 | No | 0 |
| 10 | BBC | FP | TN | 99 / 75 / 0 / 39 | No | 0 |
| 11 | GitHub sign in | TN | TN | 10 / 9 / 30 / 15 | No | 0 |
| 12 | Google account sign in | IC | IC | 99 / — / — / 99 | No | 0 |
| 13 | Python package account | TN | TN | 99 / 8 / 30 / 21 | No | 0 |
| 14 | MDN phishing education | TN | TN | 99 / 75 / 0 / 39 | No | 0 |
| 15 | GitHub phishing education | TN | TN | 38 / 29 / 0 / 20 | No | 0 |
| 16 | Amazon account sign in | IC | IC | 10 / 75 / 0 / 33 | No | 0 |
| 17 | GitHub OAuth-style query | TN | TN | 3 / 9 / 30 / 13 | No | 0 |
| 18 | Hyphenated MDN documentation URL | TN | TN | 97 / 75 / 0 / 39 | No | 0 |
| 19 | PayPal clone | TP | TP | 99 / 78 / 90 / 90 | Yes | 6 |
| 20 | Microsoft 365 clone | TP | TP | 99 / 78 / 90 / 90 | Yes | 6 |
| 21 | Google clone | TP | TP | 100 / 78 / 90 / 90 | Yes | 6 |
| 22 | Apple clone | TP | TP | 99 / 78 / 90 / 90 | Yes | 6 |
| 23 | Amazon clone on .org | TP | TP | 99 / 78 / 90 / 90 | Yes | 6 |
| 24 | Bank credential clone | TP | TP | 100 / 78 / 90 / 90 | Yes | 6 |
| 25 | IDN homograph Apple | TP | TP | 99 / 78 / 90 / 90 | Yes | 6 |
| 26 | IP and nonstandard port | TP | TP | 100 / 78 / 90 / 90 | Yes | 6 |
| 27 | Deep subdomain Microsoft | TP | TP | 100 / 78 / 90 / 90 | Yes | 6 |
| 28 | Username @ destination trick | IC | IC | — / — / — / — | Yes | 0 |
| 29 | Urgent social engineering no form | TP | TP | 99 / 75 / 0 / 75 | Yes | 5 |
| 30 | Crypto seed phrase drainer | TP | TP | 99 / 75 / 95 / 90 | Yes | 0 |
| 31 | Delayed credential form and short lure | TP | TP | 99 / 75 / 90 / 90 | Yes | 0 |
| 32 | Public Safe Browsing phishing test | TP | FN | 99 / 9 / 30 / 21 | No | 0 |
| 33 | Educational security phrases (controlled) | TN | TN | 99 / 31 / 0 / 21 | No | 0 |
| 34 | Ordinary same-site login (controlled) | TN | TN | 99 / 11 / 30 / 22 | No | 0 |
| 35 | Legitimate checkout forms (controlled) | TN | TN | 99 / 2 / 30 / 18 | No | 0 |
| 36 | Benign long OAuth URL (controlled) | TN | TN | 98 / 5 / 30 / 20 | No | 0 |
| 37 | Brand-themed education (controlled) | TN | TN | 99 / 75 / 0 / 39 | No | 0 |
| 38 | Delayed form on initially unblocked .org | FN | TP | 99 / 75 / 90 / 90 | Yes | 0 |
| 39 | Crypto drainer on .org | FN | TP | 99 / 75 / 95 / 90 | Yes | 0 |
| 40 | Microsoft clone with OAuth camouflage | FN | TP | 99 / 78 / 90 / 90 | Yes | 6 |
| 41 | Urgent lure on .org without form | FN | TP | 99 / 75 / 0 / 75 | Yes | 4 |
| 42 | Ordinary benign non-allowlisted .com | FP | TN | 99 / 0 / 0 / 9 | No | 0 |
| 43 | Lure after 10000 benign characters | FN | TP | 99 / 66 / 90 / 90 | Yes | 6 |
| 44 | Phishing on trusted hosting subdomain | FN | TP | 99 / 78 / 90 / 90 | Yes | 6 |

## Files and evidence

Main implementation files are `backend/services/risk.py`, `analyzer.py`, `url_detector.py`, `nlp_detector.py`, `dom_detector.py`, `backend/routes/status.py`, `backend/utils/validators.py`, `extension/content/content.js`, `extension/background/background.js`, `extension/shared/risk.js`, and `models/training/feature_engine.py`. New regression tests: `tests/test_targeted_fixes.py`.

- [Comparison data](D:/scam_extension/targeted-fixes-2026-10-27/comparison.json)
- [Feature run](D:/scam_extension/targeted-fixes-2026-10-27/features/browser-results.json) and [supplement](D:/scam_extension/targeted-fixes-2026-10-27/supplement/browser-results.json)
- [Three-reload reproduction](D:/scam_extension/targeted-fixes-2026-10-27/highlight-repro/browser-results.json)
- [Focused browser checks](D:/scam_extension/targeted-fixes-2026-10-27/focused/browser-results.json)
- [37-page matrix](D:/scam_extension/targeted-fixes-2026-10-27/matrix/results.json) and [seven harder cases](D:/scam_extension/targeted-fixes-2026-10-27/matrix-hard/results.json)
- [Model/feature diagnostics](D:/scam_extension/targeted-fixes-2026-10-27/model-diagnostics.json)
- [Final saved-source replay](D:/scam_extension/targeted-fixes-2026-10-27/saved-source-replay.json)
- [Backend test results](D:/scam_extension/targeted-fixes-2026-10-27/backend-results.xml)
- [Correct red popup](D:/scam_extension/targeted-fixes-2026-10-27/features/native-popup.png)

## Using the saved changes

The browser tests loaded `D:\scam_extension\phishguard-main-verification\extension`. The user's normal Chrome profile was not changed; it was last observed loading the older `D:\scam_extension\phishguard\extension`. The existing port-5000 backend was kept running and still has its pre-fix Python modules in memory. To activate this version for everyday browsing, load the repaired extension folder, use its displayed extension origin, and restart the backend from the repaired checkout. Keep the same paired token or pair again if changing it. Update the extension and backend together because the old extension recomputes the previous blocking policy.
