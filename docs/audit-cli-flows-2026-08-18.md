# Provenrail CLI/SDK Audit - 2026-08-18

Auditor: Claude Opus 5 (automated, drive-and-observe). Version audited: 0.2.30. Venv: `/Volumes/T7/Projects/AgenticTools/.venv`. Full test suite at end: **868 passed, 2 skipped, 1 warning**.

---

## Verdict Table

| Flow | Description | Verdict | Evidence |
|------|-------------|---------|----------|
| 1 | Cold-start install and first success | **PASS** | `pr quickstart --port 19878` in clean dir: server healthy in <5s, output clear, `pr demo` ran, `pr verify` passed |
| 2 | Record / bundle / verify / tamper | **PASS** | Demo bundle verified clean; `record_sig` tamper -> TAMPERING DETECTED exit 1; payload tamper -> TAMPERING DETECTED exit 1 |
| 3 | Multi-session / concurrent-writer | **PASS** | Two `FlightRecorder` instances on same stream_id; 7 records, 2 sessions; `pr verify` -> VERIFIED |
| 4 | Policy + guardrails | **PASS** | `rm -rf` via guard hook -> deny JSON on stdout, exit 0; safe cmd -> silent exit 0; localhost webhook blocked at server via 422 |
| 5 | Redaction / SCITT / tlog / OTS | **PASS (partial)** | Redaction: PII not in bundle, verification still passes. SCITT+tlog: verified with explicit pubkeys. OTS: `pr ots-verify` rejects bad input correctly; no local OTS proof to test end-to-end (no network calendar) |
| 6 | License verification | **PASS** | `verify_license(None)` -> `LicenseInfo(valid=False)`; all callers check `.valid` not `bool(result)`; dataclass truthy trap is latent but unexploited |
| 7 | Server / hosted mode | **PASS (local)** | `pr serve --open` starts, `/healthz` OK, stream provisioned, SDK ingests, `/v1/verify` returns verified. Auth/RBAC/seats with real accounts: **UNVERIFIED** (requires live Supabase) |
| 8 | Framework integrations | **PASS** | All 7 integration modules import cleanly. `instrument_anthropic` records a model call into the bundle. `ComplianceCallbackHandler` (LangChain) instantiates. README import path (`from provenrail.integrations import instrument_openai, instrument_anthropic, instrument_mcp`) works |
| 9 | Cross-language lockstep | **PASS** | `test_js_sdk_records_verify_in_python_and_js` PASSED; `test_js_sdk_tamper_is_detected` PASSED (node v22.17.1) |

---

## Findings

### [DEFECT] Bad `--tlog-pubkey` argument reports "TAMPERING DETECTED" instead of argument error

- **File:line**: `src/provenrail/verifier/verify.py:190-195`, `src/provenrail/cli.py:1154`
- **Repro**: `python -m provenrail verify bundle.json --tlog-pubkey none`
- **Observed**: `[FAIL] malformed_bundle: this bundle is structurally invalid and could not be verified (ValueError: non-hexadecimal number found in fromhex() arg at position 0)` / `RESULT: TAMPERING DETECTED` / exit 1
- **Expected**: exit 2 with a clear message that `none` is not a valid hex key, not a tamper verdict
- **Impact**: A user who typos their tlog pubkey gets a false tampering alarm. Per the README, exit 1 means "reached a verdict that is not a pass" (TAMPERING DETECTED etc.) and exit 2 means "never reached a verdict at all". This is an exit-2 situation (argument error) misclassified as exit 1 (verdict failure). Any CI gate keyed to exit 1 would fire a false alert.
- **Fix**: In `cli.py`, validate `args.tlog_pubkey` with `bytes.fromhex()` before passing to `verify_bundle()`. If validation fails, print a clear error to stderr and return 2. Same for `--witness-pubkeys`.

---

### [PAPERCUT] `FlightRecorder` exposes no public `session_id` property

- **File:line**: `src/provenrail/sdk.py:117` (chain), `src/provenrail/easy.py:358` (yield fr)
- **Repro**: `with fr.record("agent") as rec: print(rec.session_id)` -> `AttributeError: 'FlightRecorder' object has no attribute 'session_id'. Did you mean: 'session'?`
- **Observed**: AttributeError; actual value is at `rec.chain.session_id` (internal).
- **Expected**: `rec.session_id` works, or the docstring on `session()` / `record()` states how to get it.
- **Fix**: Add `@property def session_id(self) -> str: return self.chain.session_id` to `FlightRecorder`, or document the access pattern in `easy.py:record()` docstring.

---

### [PAPERCUT] `LicenseInfo` dataclass is always truthy; no `__bool__` guard

- **File:line**: `src/provenrail/license.py:67-75`
- **Repro**: `bool(verify_license("bogus")) == True` even though `.valid == False`
- **Observed**: `bool(LicenseInfo(valid=False)) = True`. A dataclass with no `__bool__` is truthy by default.
- **Impact**: Latent; all current callers correctly check `.valid`. A future caller who writes `if verify_license(key):` would silently pass for any key including invalid ones.
- **Fix**: Add `def __bool__(self) -> bool: return self.valid` to `LicenseInfo`, or add a `# WARNING: always truthy; check .valid` comment visible to callers, or both.

---

### [PAPERCUT] `httpx`->`httpx2` deprecation warning leaks through test output

- **File:line**: `src/provenrail/cli.py:18-19` (suppressed in CLI only), `pyproject.toml` (no filterwarnings)
- **Repro**: `pytest tests/` prints `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.`
- **Observed**: 1 warning in every test run (868 tests).
- **Impact**: Test noise only; users never see this via `pr` CLI.
- **Fix**: Add `filterwarnings = ["ignore::DeprecationWarning:starlette.*"]` to `[tool.pytest.ini_options]` in `pyproject.toml`, or upgrade `httpx` -> `httpx2`.

---

### [UX] OTS end-to-end demo is not locally exercisable

- **File:line**: `src/provenrail/cli.py:212` (`_cmd_ots_verify`), `bundle.json` (repo root has no `ots_proofs`)
- **Observed**: `bundle.json` at repo root has anchors but no `ots_proofs` key. `pr ots-verify` requires a `.ots` proof file generated by an OTS calendar (external network). No local fixture exists.
- **Impact**: `pr ots-verify` cannot be demonstrated or tested offline. A new user following docs cannot verify the Bitcoin anchoring path without network access.
- **Fix**: Add a pre-generated `.ots` fixture (stamped against a known digest) to `tests/fixtures/`, and a corresponding offline test that runs `pr ots-verify --data-sha256 <hex> fixture.ots`. The `ots.py` module can verify structure without Bitcoin block header confirmation.

---

### [UX] `quickstart` banner uses bare `pr`; Windows/Git Bash users hit POSIX paginator

- **File:line**: `src/provenrail/cli.py:352-367`
- **Observed**: The post-quickstart output says `pr demo`, `pr verify`, `pr export` etc. On Windows under Git Bash, `pr` is the POSIX paginator, and `pr verify bundle.json` fails with `unknown option`. README documents the workaround but the banner does not.
- **Impact**: Windows users following the quickstart banner hit a confusing failure before they see any success.
- **Fix**: Append one line to the banner: `# Windows/Git Bash: use  python -m provenrail  if pr --version says "GNU coreutils"`.

---

## What is genuinely perfect

- **Tamper detection**: Two attack vectors tested (signature flip, payload hash flip). Both caught correctly with distinct `[FAIL]` codes and exit 1. No false negatives.
- **Concurrent writers**: Two `FlightRecorder` instances on one stream, sequential sessions. Bundle verifies with 2 distinct session IDs.
- **Server localhost SSRF guard**: `/v1/webhooks` with `http://localhost:9999/hook` -> 422 with "public" in detail. Delivery also re-validates at send time (confirmed in `test_delivery_revalidates_the_url_at_send_time`).
- **Guard hook contract**: `rm -rf` -> deny JSON on stdout, exit 0. Safe command -> silent exit 0. The "always exit 0" invariant for hooks is correct and intentional.
- **JS lockstep**: Both `test_js_sdk_records_verify_in_python_and_js` and `test_js_sdk_tamper_is_detected` pass with node v22.17.1.
- **Integration imports**: All 7 integration modules (`anthropic`, `agno`, `claude_sdk`, `hermes`, `langchain`, `mcp`, `openai`) import without errors. No hard import-time dependencies.
- **Full test suite**: 868 passed, 0 failures, 16s.
