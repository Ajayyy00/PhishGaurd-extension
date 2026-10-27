# Running the repaired main-based extension

Use the checkout at `D:\scam_extension\phishguard-main-verification` on branch `fix/main-e2e-verification`.

## Start and pair

1. In Chrome, open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select this checkout's `extension` folder. No npm build is needed.
2. Open the extension's **Connection settings** (extension options). Copy the exact `chrome-extension://...` origin shown there.
3. From this checkout, use a Python environment with `backend/requirements.txt` installed. This workspace already has the dependencies and restored model weights used by the verification.
4. Set the local connection configuration and start the normal entry point:

   ```powershell
   cd D:\scam_extension\phishguard-main-verification
   $env:PHISHGUARD_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
   $env:PHISHGUARD_EXTENSION_ORIGINS = 'chrome-extension://REPLACE_WITH_THE_ORIGIN_ID_FROM_OPTIONS'
   $env:FLASK_ENV = 'production'
   Write-Host $env:PHISHGUARD_API_TOKEN  # Privately copy this into Connection settings.
   python backend/run.py
   ```

5. In Connection settings, use `http://127.0.0.1:5000/api/analyze`, paste the same token, select **Save connection**, then **Test connection**. The token field clears after saving; the token is stored privately on the extension origin.
6. Visit a page and open the PhishGuard action popup. **Rescan** extracts fresh text/DOM and bypasses both caches. The popup distinguishes full analysis from reduced protection.

Reuse the same private token environment value when restarting the server; if you generate a new token, pair the extension again. `backend/.env.example` is a reference, not an automatically loaded file. The backend binds to loopback, disables debug by default, and requires bearer authentication on the API. `/health` is public liveness only. With no token configured, protected requests fail closed.

The server initializes LightGBM and MiniLM before accepting requests. Authenticated `/api/status` reports their actual state. Missing/broken artifacts are reported; they do not become successful low-risk model predictions.

## Model files

- `models/saved/lgbm_url_model.txt` contains the exact original Git blob bytes with LF endings. `.gitattributes` preserves LF; the loader also normalizes line endings in memory.
- `models/saved/nlp_phish_model/model.safetensors` was restored from the existing local trained model. SHA-256: `fd7e4c1e3452ad211703596f43ead4a14c4d4d217b066aaa1a775ee4cd0eb38e`.
- The weight file remains ignored by Git, as before. A fresh clone must provision these trained weights separately alongside the existing config/tokenizer files. No training or model download occurs at startup.

## Reproduce verification

From the repository root:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'backend')
python -X utf8 -m pytest backend/tests -q -p no:cacheprovider
python -X utf8 -m pytest backend/tests tests/test_main_repair.py -q -p no:cacheprovider
node --test tests/extension.test.cjs
python -X utf8 -u tests/e2e/probe_models.py
```

The original four test bodies are unchanged. Root `conftest.py` gives their Flask test transport a random bearer header. This authenticates the requests rather than bypassing application security. Explicit unauthenticated requests are separately required to return 401, including with `TESTING=True`.

Real-browser tests require Playwright, a Chrome binary supporting unpacked-extension automation, and free ports 5000 and 8766:

```powershell
$env:PLAYWRIGHT_MODULE = 'ABSOLUTE_PATH_TO_NODE_MODULES/playwright'
$env:PYTHON = 'ABSOLUTE_PATH_TO_YOUR_PYTHON/python.exe'
$env:CHROME_PATH = 'ABSOLUTE_PATH_TO_CHROME_FOR_TESTING/chrome.exe'
$env:HEADED = '1'  # Visible browser; omit for headless.
node tests/e2e/verify-browser.cjs
```

The harness has defaults for this workstation. It creates an isolated profile, loads the real extension, starts the actual `backend/run.py`, pairs through the options UI, operates the native popup, and stops its own browser/server afterward. Tokens are random and excluded from evidence. Profiles reside in the OS temp directory, outside Git.

The Safe UI fixture uses `fixture.github.com` mapped to loopback **only inside the test browser**, exercising the existing trusted-domain policy. A separate localhost observation records the existing URL-model false positive. Neither this fixture nor the 25 functional checks is a broad accuracy benchmark. The test browser blocks unrelated external resources and uses fake local forms with no credential submission.

See [the repair report](../MAIN_REPAIR_REPORT.md) for exact results, browser version, changes to the diagnostic setup, and remaining limits.
