# Verification integrity

The unchanged historical diagnostic scripts and their failures remain in `D:\scam_extension\main-verification-2026-10-24`. They were not overwritten. The repaired, reproducible tests are in this checkout.

The historical harness cannot literally achieve all 25 assertions with a secured, correctly blocking extension:

1. It uses unauthenticated calls for every successful API assertion, then asserts that the *same previously recorded response* was HTTP 401. Requests now have explicit authenticated/unauthenticated transports, with an actual 401 rejection check.
2. It reads the phishing page after expecting the extension to redirect away to a warning. The new sequence asserts that real warning, then actually clicks Proceed Anyway before requiring full text/DOM inference and highlighting.
3. It compares the initial URL warning with a prior full-page result. The new comparison uses the same URL-only stage, and separately asserts the full weighted score and every detector bar.
4. Its Go Back assertion hardcodes an external Google destination. The repaired offline-safe behavior goes to `about:blank`; the test checks that destination directly. Its offline text assertion now checks the explicit `Reduced protection` label.
5. Once the actual URL model is connected, localhost receives the known false-positive score 100. The Safe UI fixture now uses the **existing** trusted-domain policy on a hostname mapped locally; the genuine localhost result is still saved as `localhostModelAccuracy`, not reported as an accuracy success. No allowlist or model weight was changed for the fixture.

The new harness retains 25 functional checks and strengthens them with actual options pairing, model-ready status, formula equality, forced network rescans, literal XSS text checks, and native-popup computed colors/geometry after animation. There are no mocked successful API responses or hidden failed checks; any failed check exits nonzero.

The model probes now use default artifact locations exclusively, send real bearer credentials for API calls, assert successful model loading and inference, and verify the URL-only/full cache transition. They do not supply alternate detectors or artifact paths.

`backend/tests/test_api.py` and its assertions remain byte-for-byte unchanged. Root `conftest.py` supplies credentials to the original test transport; it does not disable authorization, replace detectors, or fake responses. The new API regressions explicitly verify that missing authentication still fails in testing mode.
