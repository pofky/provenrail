"""Unified `fr` command line: serve, demo, verify, report."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import warnings
from pathlib import Path

# Suppress a transitive dependency deprecation (Starlette's TestClient warning about
# httpx) that the in-process demo/quickstart sink imports trigger. It is internal,
# actionable only by upstream, and would otherwise print a scary line above the clean
# `pr demo` / `pr verify` output a first-time user follows in the /start guide.
warnings.filterwarnings("ignore", message=r".*starlette\.testclient.*")
warnings.filterwarnings("ignore", module=r"starlette\.testclient")


def _cmd_serve(args) -> int:
    import uvicorn

    from .anchor import LocalAnchor, RFC3161Anchor
    from .server.app import create_app

    anchor = RFC3161Anchor(args.tsa) if args.anchor == "rfc3161" else LocalAnchor()
    app = create_app(args.db, anchor=anchor, auto_anchor_interval=args.anchor_interval,
                     require_account=not args.open)
    import provenrail.server.app as appmod
    appmod.app = app
    mode = "open (no API key)" if args.open else "API-key required"
    base = f"http://{args.host}:{args.port}"
    print(f"Provenrail serving on {base} "
          f"(db={args.db}, anchor={args.anchor} every {args.anchor_interval}s, {mode})")
    print(f"  Run Explorer dashboard: {base}/app")
    print(f"  Hosted verifier:        {base}/verify")
    from . import license as lic
    _tok = lic.load_license_token()
    _li = lic.verify_license(_tok)
    if _li.valid:
        print(f"  Commercial license:     {_li.plan} tier active (verified offline)")
    elif _tok:
        # A token is present but does not verify (commonly expired after a billing period).
        # Say so loudly: otherwise the server silently drops to the free tier with no hint.
        print(f"  Commercial license:     not active ({_li.reason}). "
              "Copy the current key from provenrail.com/account and run `pr activate <key>`.")
    # uvicorn.run blocks forever; flush now so the banner reaches a redirected stdout
    # (docker/systemd/`> log &`) immediately, not only when the process eventually exits.
    sys.stdout.flush()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def _cmd_activate(args) -> int:
    """Verify a commercial license key offline and store it so `pr serve` unlocks the tier."""
    from datetime import UTC, datetime

    from . import license as lic
    token = args.key.strip()
    info = lic.verify_license(token)
    if not info.valid:
        print(f"License key invalid: {info.reason}", file=sys.stderr)
        if info.reason == "license expired":
            print("Copy the current key from provenrail.com/account (it refreshes each billing "
                  "period) and run `pr activate <key>` again.", file=sys.stderr)
        return 1
    path = lic.save_license_token(token)
    when = ("no expiry" if not info.expires_at
            else "expires " + datetime.fromtimestamp(info.expires_at, UTC).strftime("%Y-%m-%d"))
    print(f"License valid: {info.plan} tier ({when}). Verified offline, nothing was sent anywhere.")
    print(f"Saved to {path}; `pr serve` now runs at the {info.plan} tier.")
    print(f"Or pass it explicitly:  export PROVENRAIL_LICENSE={token}")
    return 0


def _cmd_demo(args) -> int:
    """Run a self-contained agent session and emit a verifiable bundle + pin."""
    from fastapi.testclient import TestClient

    from .anchor import LocalAnchor, RFC3161Anchor
    from .ingest_client import provision_stream
    from .sdk import FlightRecorder
    from .server.app import create_app
    from .server.witness import LocalWitness

    anchor = RFC3161Anchor(args.tsa) if args.anchor == "rfc3161" else LocalAnchor()
    # A bundled reference witness so the demo shows the full witnessed (green) path: an
    # independent cosigner makes the transparency-log head un-equivocable. In production the
    # witness runs on separate infrastructure; here it is in-process purely to demonstrate.
    witness = LocalWitness("demo-witness")
    app = create_app(":memory:", anchor=anchor, require_account=False, tlog_witnesses=[witness])
    client = TestClient(app)
    prov = provision_stream("http://demo", http=client)

    fr = FlightRecorder("http://demo", prov["write_token"], prov["stream_id"],
                        http=client, pin_path=args.pin)

    @fr.tool("web_search")
    def web_search(q):
        return {"results": 3, "top": "example.com"}

    with fr.session({"agent": "demo-agent", "task": "research and summarize"}):
        fr.record_model_call("anthropic", "claude-opus-4-8",
                             request={"prompt": "Research X and summarize"},
                             response={"text": "Here is a summary"},
                             usage={"input": "812", "output": "240"})
        web_search("what is X")
        fr.record_decision("answer is grounded; returning to user", confidence="high")
        fr.record_human_oversight("approved", approver="freelancer@example.com")

    client.post(f"/v1/streams/{prov['stream_id']}/anchor",
                headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = client.get(f"/v1/streams/{prov['stream_id']}/export",
                        headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    meta = client.get("/v1/meta").json()
    log_pubkey = meta["tlog_pubkey"]
    witness_pubkey = witness.public_key_hex()

    print(f"Recorded a {len(bundle['records'])}-event demo run and sealed it into {args.out}.")
    print()
    print("Now prove it is tamper-evident. Re-derive every hash and signature, trusting nothing:")
    print(f"  pr verify {args.out}")
    print()
    print(f"Then change one character in {args.out}, save, and verify again: it will refuse to pass.")
    print()
    print("Optional, once you have seen that:")
    print(f"  pr report --regime eu-ai-act {args.out} --md     a readable attestation")
    print(f"  pr verify {args.out} --pin {args.pin}            also check the client pin")
    print( "  verify the public transparency log and its independent witness cosignature:")
    print(f"    pr verify {args.out} \\")
    print(f"      --tlog-pubkey {log_pubkey} \\")
    print(f"      --witness-pubkeys demo-witness={witness_pubkey}")
    return 0


def _cmd_verify(args) -> int:
    from .verifier.verify import main as verify_main
    argv = [args.bundle]
    if args.pin:
        argv += ["--pin", args.pin]
    if args.openings:
        argv += ["--openings", args.openings]
    if getattr(args, "tlog_pubkey", None):
        argv += ["--tlog-pubkey", args.tlog_pubkey]
    if getattr(args, "witness_pubkeys", None):
        argv += ["--witness-pubkeys", args.witness_pubkeys]
    if getattr(args, "registry_pubkey", None):
        argv += ["--registry-pubkey", args.registry_pubkey]
    for hdr in getattr(args, "bitcoin_header", None) or []:
        argv += ["--bitcoin-header", hdr]
    if args.json:
        argv += ["--json"]
    return verify_main(argv)


def _cmd_verify_content(args) -> int:
    """Prove that a transcript you hold is exactly what was recorded.

    By default Provenrail stores a SHA-256 fingerprint of each prompt/response, not the text
    (privacy). That fingerprint is only useful if a recipient can check their copy of the content
    against it. This command does that: it canonicalizes the content the same way the recorder did,
    hashes it, and reports which recorded field (if any) that hash matches. A match proves the
    content is authentic and unaltered; a mismatch proves it differs from what was recorded."""
    from .canonical import hash_value
    bundle = json.loads(open(args.bundle, encoding="utf-8").read())
    raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
    try:
        content = json.loads(raw)
    except json.JSONDecodeError:
        content = raw  # allow a plain-text transcript, hashed as a JSON string
    target = hash_value(content)

    matches = []
    for sr in bundle.get("records", []):
        rec = sr.get("record", sr)
        payload = rec.get("payload", {})
        for field, val in payload.items():
            if isinstance(val, dict) and val.get("hash") == target:
                if args.field and field != args.field:
                    continue
                if args.seq is not None and rec.get("seq") != args.seq:
                    continue
                matches.append({"seq": rec.get("seq"), "action_type": rec.get("action_type"),
                                "field": field})

    if args.json:
        print(json.dumps({"content_sha256": target, "matched": bool(matches),
                          "matches": matches}, indent=2))
        return 0 if matches else 1
    if matches:
        print(f"MATCH: this content is recorded in the bundle (sha256 {target[:16]}...).")
        for m in matches:
            print(f"  seq {m['seq']} {m['action_type']}.{m['field']}")
        print("The record is tamper-evident, so this proves the content above is authentic and "
              "was not altered after recording.")
        return 0
    scope = ""
    if args.seq is not None or args.field:
        scope = f" at the requested location (seq={args.seq}, field={args.field})"
    print(f"NO MATCH: this content (sha256 {target[:16]}...) does not match any recorded "
          f"fingerprint{scope}.")
    print("Either it is not the content that was recorded, or it was altered. If the record used "
          "redaction, disclose it with `pr disclose` instead.")
    return 1


def _cmd_ots_verify(args) -> int:
    """Verify an OpenTimestamps (Bitcoin) proof offline: replay its operations and report which
    Bitcoin block it anchors to. Supply --data-sha256 (the SHA-256 of what was stamped) and, to
    fully confirm, one or more --block-root height=merkle_root from a Bitcoin header you trust."""
    from . import ots
    data_hex = args.data_sha256
    if not data_hex:
        # Default: stamp target is the file's own SHA-256.
        with open(args.proof.replace(".ots", ""), "rb") as fh:
            data_hex = __import__("hashlib").sha256(fh.read()).hexdigest()
    roots: dict[int, str] = {}
    for pair in args.block_root or []:
        h, _, root = pair.partition("=")
        roots[int(h)] = root
    with open(args.proof, "rb") as fh:
        proof = fh.read()
    verdict = ots.verify_ots(proof, data_hex, bitcoin_block_merkle_roots=roots or None)
    if args.json:
        print(json.dumps(verdict, indent=2))
        return 0 if verdict["ok"] else 1
    if not verdict["structurally_valid"]:
        print(f"INVALID: {verdict['error']}")
        return 1
    print(f"data matches stamped digest: {verdict['data_matches']}")
    for b in verdict["bitcoin"]:
        state = ("CONFIRMED" if b["confirmed"] else "MISMATCH") if b["confirmed"] is not None \
            else "attested (supply --block-root to confirm)"
        print(f"Bitcoin block {b['height']}: merkle root {b['merkle_root_hex']} [{state}]")
    for uri in verdict["pending"]:
        print(f"pending calendar (not yet confirmed in Bitcoin): {uri}")
    print("OK" if verdict["ok"] else "NOT fully confirmed")
    return 0 if verdict["ok"] else 1


def _cmd_disclose(args) -> int:
    """Render a human-readable disclosed view of a bundle using an operator openings keystore.
    Fields with a valid opening are revealed; withheld or erased fields show as __withheld__."""
    from .redaction import disclose
    from .verifier.verify import load_openings
    bundle = json.loads(open(args.bundle, encoding="utf-8").read())
    openings = load_openings(json.loads(open(args.openings, encoding="utf-8").read())
                             if args.openings else None)
    out = []
    for sr in bundle.get("records", []):
        rec = sr.get("record", sr)
        out.append({"seq": rec.get("seq"), "action_type": rec.get("action_type"),
                    "payload": disclose(rec.get("payload", {}), openings)})
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


def _cmd_quickstart(args) -> int:
    """One command to a working setup: start a local sink, provision a stream, and write a
    .provenrail.json so `with provenrail.record('agent'):` works with no further config."""
    import time

    import httpx

    from .easy import CONFIG_FILENAME, write_config
    from .ingest_client import provision_stream

    pid_file = Path(".provenrail.pid")

    if args.stop:
        if pid_file.is_file():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGTERM)
            except (OSError, ValueError):
                pass
            pid_file.unlink(missing_ok=True)
            print("stopped the local Provenrail sink")
        else:
            print("no local sink pid file found")
        return 0

    if args.url:
        # Provision against an already-running sink (yours, or a hosted one).
        prov = provision_stream(args.url, label=args.label, api_key=args.account_key)
        cfg = write_config(CONFIG_FILENAME, endpoint=args.url,
                           write_token=prov["write_token"], stream_id=prov["stream_id"],
                           read_token=prov.get("read_token"), share_token=prov.get("share_token"))
        print(f"wrote {cfg}")
    else:
        # Start a local sink in the background (open mode), wait until healthy, provision.
        url = f"http://127.0.0.1:{args.port}"
        proc = subprocess.Popen(
            [sys.executable, "-m", "provenrail.cli", "serve", "--open",
             "--port", str(args.port), "--db", args.db, "--anchor", args.anchor],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid_file.write_text(str(proc.pid))
        deadline = 20
        for _ in range(deadline * 5):
            try:
                if httpx.get(f"{url}/healthz", timeout=1.0).status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            proc.terminate()
            print("the local sink did not become healthy in time")
            return 1
        prov = provision_stream(url, label=args.label)
        cfg = write_config(CONFIG_FILENAME, endpoint=url,
                           write_token=prov["write_token"], stream_id=prov["stream_id"],
                           read_token=prov.get("read_token"), share_token=prov.get("share_token"))
        print(f"started a local sink (pid {proc.pid}) and wrote {cfg}")

    print("\nNow your whole setup is two lines:\n")
    print("    import provenrail as fr")
    print("    with fr.record('my-agent'):")
    print("        ...   # your agent runs; calls are captured automatically\n")
    print("After your agent runs, export your own run and verify it yourself:\n")
    print("    pr export my-run.json     # pulls your sealed run from the sink")
    print("    pr verify my-run.json     # recomputes everything, trusts nobody\n")
    print("Optional: block risky actions, not just record them. Add prebuilt guardrails")
    print(f"to {CONFIG_FILENAME}:\n")
    print('    "policy": {"use": ["destructive", "secrets", "money"]}\n')
    print("    pr rules                    # list every pack and rule")
    print("    pr rules --check my-run.json  # which rules match YOUR tool names\n")
    print("Stop the local sink with:  pr quickstart --stop")
    return 0


def _cmd_diff(args) -> int:
    from .replay import diff_runs
    a = json.loads(open(args.bundle_a, encoding="utf-8").read())
    b = json.loads(open(args.bundle_b, encoding="utf-8").read())
    out = diff_runs(a, b)
    if args.json:
        print(json.dumps(out, indent=2))
        return 0
    s = out["summary"]
    if not out.get("verified_a", True) or not out.get("verified_b", True):
        print("WARNING: one or both bundles failed verification; diff may be over tampered data")
    print(f"equal {s['equal']}  changed {s['changed']}  added {s['added']}  removed {s['removed']}")
    for step in out["steps"]:
        mark = {"equal": "  ", "changed": " ~", "added": " +", "removed": " -"}[step["tag"]]
        print(f"{mark} {step['action_type']}: {step['primary']}")
    print("\nIDENTICAL" if s["identical"] else "\nRUNS DIFFER")
    return 0


def _cmd_sidecar(args) -> int:
    """Run the out-of-process capture sidecar in front of a model API. Point your agent's
    model client base URL at this proxy; every call is recorded from a separate process the
    agent does not control. Lock model egress to this proxy to make capture mandatory."""
    import uvicorn

    from .easy import make_recorder
    from .sidecar import create_sidecar_app

    recorder = make_recorder(args.label)
    app = create_sidecar_app(recorder, args.upstream, provider=args.provider,
                             fail_closed=args.fail_closed)
    base = f"http://{args.host}:{args.port}"
    print(f"Provenrail sidecar proxying -> {args.upstream}")
    print(f"  listen: {base}   (point your model client's base_url here)")
    print(f"  stream: {recorder.stream_id}")
    print(f"  mode:   {'fail-closed (refuse uninstrumented calls)' if args.fail_closed else 'fail-open'}")
    print("  Reminder: lock outbound model egress to this proxy or the guarantee is only a default.")
    sys.stdout.flush()  # show the banner immediately under a redirected log, before the blocking run
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def _cmd_witness(args) -> int:
    """Run a standalone, out-of-process C2SP witness. Deploy this on infrastructure that is
    independent of the sink so its cosignatures actually mean something: a witness co-located
    with the sink it witnesses provides no protection against a dishonest operator."""
    import uvicorn

    from .server.witness import PersistentWitness, WitnessStore, create_witness_app

    log_keys: dict[str, str] = {}
    for pair in args.log or []:
        if "=" not in pair:
            print(f"--log expects origin=pubkey_hex, got {pair!r}")
            return 1
        origin, pub = pair.split("=", 1)
        log_keys[origin] = pub
    store = WitnessStore(args.db)
    witness = PersistentWitness(args.name, store, log_keys=log_keys or None)
    if not log_keys:
        print("WARNING: no --log pins given; this witness will cosign any checkpoint and so "
              "provides no real protection. Pin every log you witness with --log origin=pubkey.")
    app = create_witness_app(witness)
    print(f"Provenrail witness '{args.name}' on http://{args.host}:{args.port}")
    print(f"  public key: {witness.public_key_hex()}")
    print(f"  witnessing: {sorted(log_keys) or '(unpinned, insecure)'}")
    print("  Give the sink operator this URL + public key to add as a witness.")
    # Flush before the blocking server run so a redirected log (docker/systemd) shows the
    # banner and public key immediately, instead of looking like a witness that never started.
    sys.stdout.flush()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def _cmd_export(args) -> int:
    """Pull your own recorded run out of the sink as a verifiable bundle, then you can
    `pr verify` it yourself. Uses the read token saved in .provenrail.json by `pr quickstart`,
    so a local user can close the full loop (record -> export -> verify) with no account."""
    import httpx

    from .easy import _load_config_file

    cfg = _load_config_file()
    endpoint = os.environ.get("PROVENRAIL_URL") or cfg.get("endpoint")
    stream_id = args.stream or os.environ.get("PROVENRAIL_STREAM_ID") or cfg.get("stream_id")
    read_token = os.environ.get("PROVENRAIL_READ_TOKEN") or cfg.get("read_token")

    if not (endpoint and stream_id):
        print("no Provenrail config found in this folder. Run `pr quickstart` first, or pass "
              "--stream and set PROVENRAIL_URL.")
        return 1
    if not read_token:
        print("no read token found. Re-run `pr quickstart` to refresh .provenrail.json (this "
              "version saves a read token), or set PROVENRAIL_READ_TOKEN.")
        return 1

    headers = {"Authorization": f"Bearer {read_token}"}
    base = endpoint.rstrip("/")
    try:
        # Best effort: take a fresh anchor so the exported run carries a sealed checkpoint. A
        # failure here (already anchored, or the sink declines) never blocks the export.
        httpx.post(f"{base}/v1/streams/{stream_id}/anchor", headers=headers, timeout=15.0)
        resp = httpx.get(f"{base}/v1/streams/{stream_id}/export", headers=headers, timeout=30.0)
    except httpx.HTTPError as e:
        print(f"could not reach the sink at {endpoint}: {e}")
        print("is it still running? `pr quickstart` starts it; `pr quickstart --stop` stops it.")
        return 1
    if resp.status_code != 200:
        print(f"export failed ({resp.status_code}): {resp.text[:200]}")
        return 1

    bundle = resp.json()
    Path(args.out).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    n = len(bundle.get("records", []))
    a = len(bundle.get("anchors", []))
    if n == 0:
        # Exporting nothing is almost always a mistake (the agent never connected, or ran against
        # a different stream). Say so plainly instead of handing back a bundle that then verifies
        # as "no records".
        print(f"wrote {args.out}, but it has 0 records: nothing has been recorded on this stream "
              f"yet.")
        print("Run your agent (with `import provenrail as fr; with fr.record(...)`) while the "
              "recorder is up, then export again. Is this the right folder/stream?")
        return 1
    print(f"wrote {args.out} ({n} records, {a} anchors). Verify it yourself with:\n")
    print(f"    pr verify {args.out}")
    return 0


def _cmd_pack(args) -> int:
    from .pack import build_pack
    bundle = json.loads(open(args.bundle, encoding="utf-8").read())
    pin = json.loads(open(args.pin, encoding="utf-8").read()) if args.pin else None
    data = build_pack(bundle, regime=args.regime, pin=pin)
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"Wrote {len(data)} byte evidence pack to {args.out} (regime={args.regime})")
    print("Contents: bundle.json, attestation, VERIFY.txt, MANIFEST.json"
          + (", pin.json" if pin else ""))
    return 0


def _cmd_rules(args) -> int:
    """List the prebuilt guardrail catalogue, or check it against a real recorded run.

    The catalogue matches on tool names and argument text, and every codebase names its
    tools differently, so a pack is an informed guess about your naming rather than proof
    of coverage. `--check` replaces the guess with evidence: it reports which of the tool
    names in an actual bundle each rule would have matched. A rule matching nothing is
    either irrelevant to you or named wrong for your tools.
    """
    import fnmatch

    from . import rulesets

    if args.check:
        bundle = json.loads(open(args.check, encoding="utf-8").read())
        tools = sorted({(r.get("record", r) or {}).get("payload", {}).get("tool")
                        for r in bundle.get("records", [])
                        if (r.get("record", r) or {}).get("action_type") in
                        ("tool_call", "mcp_call")} - {None})
        if not tools:
            print("No tool calls in this bundle, so there is nothing to check rules against.")
            return 0
        selected = args.use.split(",") if args.use else rulesets.pack_ids()
        try:
            rules = rulesets.resolve(selected)
        except rulesets.UnknownRuleError as e:
            print(f"error: {e}")
            return 2
        print(f"Tool names in this run ({len(tools)}): {', '.join(tools)}\n")
        matched_any = False
        for rule in rules:
            pattern = rule.get("tool", "*")
            hits = [t for t in tools if fnmatch.fnmatch(t.lower(), pattern.lower())]
            if rule.get("arg_contains") and pattern == "*":
                # Content rules match argument text, which is hashed by default, so name
                # matching cannot answer for them. Say so rather than imply coverage.
                print(f"  [content] {rule['id']}: matches on argument text, not tool names; "
                      "cannot be checked from names alone")
                continue
            if hits:
                matched_any = True
                print(f"  MATCHES   {rule['id']}  ->  {', '.join(hits)}")
            else:
                print(f"  no match  {rule['id']}  (pattern {pattern})")
        if not matched_any:
            print("\nNo name-based rule matched any tool in this run. Either these packs do "
                  "not apply to your agent, or your tools are named differently from the "
                  "patterns. Write custom rules for your actual tool names.")
        return 0

    if args.json:
        print(json.dumps({"packs": {k: {"title": v["title"],
                                        "description": v["description"],
                                        "rules": v["rules"]}
                                    for k, v in rulesets.CATALOG.items()}}, indent=2))
        return 0

    print("Prebuilt guardrail packs. Nothing is enabled by default.\n")
    print('Enable in .provenrail.json:  {"policy": {"use": ["destructive", "secrets"]}}')
    print("You can name a whole pack, or a single rule id, and mix with your own rules.\n")
    for pack, spec in rulesets.CATALOG.items():
        print(f"{pack}  ({spec['title']})")
        print(f"  {spec['description']}")
        for rule in spec["rules"]:
            target = rule.get("tool") or f"args ~ {rule.get('arg_contains', '')[:34]}"
            cap = f" max={rule['max_per_session']}" if rule.get("max_per_session") else ""
            print(f"    {rule['effect']:18} {rule['id']:38} {target}{cap}")
            if args.verbose and rule.get("note"):
                print(f"      note: {rule['note']}")
        print()
    if not args.verbose:
        print("Run with --verbose to see each rule's false-positive note.")
    print("These match tool NAMES and argument text, and every codebase names tools")
    print("differently, so enabling a pack is not proof of coverage. Check against a real")
    print("run:  pr rules --check bundle.json")
    return 0


def _cmd_risk(args) -> int:
    """Show every action a policy blocked in a bundle, newest last.

    The record already contains this, but reading raw JSON is not a review workflow. This
    is the offline counterpart to the dashboard's policy view: an auditor with only a
    bundle can answer "what did this agent try that it was not allowed to do?".
    """
    from .server.alerts import AlertEngine

    bundle = json.loads(open(args.bundle, encoding="utf-8").read())
    records = bundle.get("records", [])
    denials = AlertEngine.denials_in(records)

    decisions = [r.get("record", r) for r in records
                 if (r.get("record", r) or {}).get("action_type") == "policy.decision"]
    # An escalation ("a human was asked") is neither a block nor a clean allow, and counting
    # it as either misreports what the guardrail did.
    escalated = [d for d in decisions
                 if str((d.get("payload") or {}).get("effect", "")).lower() == "require_oversight"]
    allows = len(decisions) - len(denials) - len(escalated)

    if args.json:
        print(json.dumps({"denials": denials, "allowed": allows,
                          "escalated_to_human": len(escalated),
                          "policy_enforced": bool(decisions)}, indent=2))
        return 1 if denials else 0

    if not decisions:
        print("No policy decisions in this bundle.")
        print("Nothing was blocked because no policy was in force, which is NOT the same as")
        print("the agent having done nothing risky. Configure a policy to change that:")
        print("  https://provenrail.com/docs#policy")
        return 0

    escalated_note = f", {len(escalated)} escalated to a human" if escalated else ""
    print(f"Policy decisions: {len(decisions)} ({allows} allowed, {len(denials)} DENIED"
          f"{escalated_note})\n")
    if not denials:
        print("No action was blocked. Every evaluated call was permitted by the policy.")
        return 0

    by_rule: dict[str, int] = {}
    for d in denials:
        rule = d.get("rule") or "?"
        by_rule[rule] = by_rule.get(rule, 0) + 1
        print(f"  DENIED  {d.get('ts_utc', '?')}  {d.get('event_type', '?')} "
              f"{d.get('target', '?')}")
        print(f"          rule={d.get('rule', '?')}  reason={d.get('reason', '')}")
        print(f"          session={d.get('session_id', '?')} seq={d.get('seq', '?')}")
    print("\nBlocked by rule:")
    for rule, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        print(f"  {n:4}  {rule}")
    print("\nThese decisions are part of the signed chain: run `pr verify` to prove they")
    print("were recorded at the time and have not been edited since.")
    return 1  # non-zero so CI can gate on "the agent tried something forbidden"


def _cmd_spend(args) -> int:
    """Estimated spend: from a bundle (one run) or the local ledger (across runs).

    Deliberately two sources, because they answer two different questions. A bundle answers
    "what did this run cost, and can I prove the record it was computed from is unaltered?".
    The ledger answers "what has this agent cost me today, this week, in total?", which is
    the question that gets asked after an overnight run and which no single bundle can
    answer.

    Every number here is an ESTIMATE from reported token usage and a public price table.
    It is labelled as such in the output, because a finance team acting on a number that
    quietly disagrees with the provider's invoice is worse off than one with no number.
    """
    from . import pricing
    from . import spend as spend_ledger

    table = pricing.load_price_table()
    stale = pricing.is_stale(table)
    as_of = pricing.table_as_of(table)
    overrides = sum(1 for p in table.values() if p.source == "override")

    if args.bundle:
        from .server import analytics
        bundle = json.loads(open(args.bundle, encoding="utf-8").read())
        records = [r.get("record", r) for r in bundle.get("records", [])]
        summary = analytics.summarize([{"record": r} for r in records])
        if args.json:
            print(json.dumps({**summary, "estimated": True, "prices_as_of": as_of,
                              "prices_stale": stale}, indent=2))
            return 0
        totals = summary.get("totals", summary)
        print(f"Estimated spend for {args.bundle}")
        print(f"  cost        ${totals.get('cost_usd', 0.0):.4f}")
        print(f"  tokens      {totals.get('tokens_in', 0):,} in / "
              f"{totals.get('tokens_out', 0):,} out")
        if totals.get("unpriced_calls"):
            print(f"  unpriced    {totals['unpriced_calls']} model call(s) had no known price "
                  f"and contribute $0.00, so this total is a FLOOR, not the full cost")
    else:
        rep = spend_ledger.report(agent_id=args.agent)
        if args.json:
            print(json.dumps({**rep, "prices_as_of": as_of, "prices_stale": stale}, indent=2))
            return 0
        if not rep["agents"]:
            print("No local spend recorded yet.")
            print(f"The ledger ({spend_ledger.ledger_path()}) is written only when a policy "
                  "declares a")
            print("cross-session budget (scope \"day\" or \"total\"). Add one to track spend "
                  "between runs:")
            print('  {"policy": {"budgets": [{"scope": "day", "limit_usd": 25}]}}')
            return 0
        def money(value: float) -> str:
            return f"${value:,.4f}".rjust(13)

        print(f"{'agent':<28}{'today':>13}{'7d':>13}{'30d':>13}{'total':>13}")
        for row in rep["agents"]:
            print(f"{row['agent_id'][:27]:<28}{money(row['today_usd'])}"
                  f"{money(row['last_7d_usd'])}{money(row['last_30d_usd'])}"
                  f"{money(row['total_usd'])}")
        print(f"{'all agents':<28}{'':>13}{'':>13}{'':>13}{money(rep['total_usd'])}")

    note = f"prices verified {as_of}" if as_of else "prices undated"
    if overrides:
        note += f", {overrides} overridden from {pricing.PRICES_FILENAME}"
    print(f"\nEstimate only ({note}). Reconcile against your provider invoice before "
          f"billing anyone.")
    if stale:
        print("WARNING: the price table has not been verified recently, so these figures may "
              "be wrong.")
        print(f"Set current rates in {pricing.PRICES_FILENAME} (also the right place for "
              "negotiated rates).")
    return 0


def _cmd_reconcile(args) -> int:
    """Compare recorded estimates against a provider invoice or usage export.

    The question that turns a cost estimate into something finance can use is "does this
    match the bill?". Spend on the invoice that no recorded run accounts for is the finding
    worth the whole feature: it means calls happened outside the recorder.
    """
    from .reconcile import reconcile, render_text

    bundle = json.loads(open(args.bundle, encoding="utf-8").read())
    invoice_csv = open(args.invoice, encoding="utf-8").read()
    records = bundle.get("records", [])
    result = reconcile([(bundle.get("stream_id", "bundle"), records)], invoice_csv,
                       since=args.since, until=args.until)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_text(result))
    # Non-zero when the invoice contains spend no recorded run explains, so CI or a finance
    # cron can gate on "something is billing us that we are not recording".
    return 1 if result["totals"]["unaccounted_on_invoice_usd"] > 0 else 0


def _cmd_report(args) -> int:
    from .reports import generate_attestation, render_markdown
    bundle = json.loads(open(args.bundle, encoding="utf-8").read())
    pin = json.loads(open(args.pin, encoding="utf-8").read()) if args.pin else None
    if args.html:
        from .evidence_report import render_report_html
        witnesses = dict(p.split("=", 1) for p in (args.witness_pubkeys or []))
        out = render_report_html(bundle, tlog_log_key=args.tlog_pubkey,
                                 witness_pubkeys=witnesses or None, pin=pin)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"Wrote auditor verification report to {args.out} (open in a browser, print to PDF)")
        else:
            print(out)
        return 0
    att = generate_attestation(bundle, regime=args.regime, pin=pin)
    if args.md:
        print(render_markdown(att))
    else:
        print(json.dumps(att, indent=2))
    return 0 if att["integrity"]["verified"] else 1


def _cmd_guard(args) -> int:
    """Guardrails for a coding agent, at its own tool boundary, with a signed receipt."""
    from . import guard
    from .easy import CONFIG_FILENAME, _load_config_file, load_policy

    action = args.action or "status"

    if action == "hook":
        code, out, err = guard.run_hook(sys.stdin.read(), default_event=args.event)
        if out:
            print(out)
        if err:
            sys.stderr.write(err)
        return code

    if action == "install":
        if not (_load_config_file() or {}).get("endpoint"):
            print("No Provenrail endpoint configured in this folder, so decisions could be")
            print("enforced but not recorded. Run `pr quickstart` first (it starts a local")
            print("sink and writes .provenrail.json), then `pr guard install`.")
            return 1
        packs = guard.arm_default_policy(args.use.split(",") if args.use else None)
        path = guard.install_claude_hooks()
        print(f"Armed guardrails in {CONFIG_FILENAME}: {', '.join(packs)}")
        print(f"Installed Claude Code hooks in {path}\n")
        print("From the next Claude Code session in this folder:")
        print("  - a destructive command is BLOCKED before it runs (rm -rf, terraform")
        print("    destroy, force push, DROP TABLE, world-writable chmod, leaked keys)")
        print("  - an action needing a human is turned into a permission prompt, and your")
        print("    answer is recorded as oversight")
        print("  - every decision is signed and hash-chained\n")
        print("  pr guard status     what is armed, and what it has blocked")
        print("  pr guard receipt    export the proof and verify it yourself")
        print("  pr guard uninstall  remove the hooks (your own hooks are left alone)\n")
        print("Honest scope: this covers tool calls Claude Code routes through its hooks.")
        print("It cannot constrain a process that never calls them.")
        return 0

    if action == "uninstall":
        path, removed = guard.uninstall_claude_hooks()
        print(f"removed {removed} Provenrail hook entr{'y' if removed == 1 else 'ies'} from {path}"
              if removed else f"no Provenrail hooks found in {path}")
        print(f"The policy in {CONFIG_FILENAME} is untouched; delete its \"policy\" block to disarm.")
        return 0

    if action == "reset":
        guard.reset_counts()
        print("Cleared the per-session blast-radius counters "
              f"({guard.COUNTS_FILENAME}). Deny and oversight rules are unaffected;")
        print("they never depended on those counters.")
        return 0

    if action == "receipt":
        rc = _cmd_export(argparse.Namespace(out=args.out, stream=None))
        if rc != 0:
            return rc
        print()
        return _cmd_risk(argparse.Namespace(bundle=args.out, json=False))

    # status
    from .easy import find_config_file
    cfg = _load_config_file() or {}
    policy = load_policy(cfg.get("policy"))
    installed = guard.hooks_installed()
    pending = guard.read_journal()
    source = find_config_file()
    print(f"Claude Code hooks : {'installed' if installed else 'NOT installed'} "
          f"({guard.CLAUDE_SETTINGS})")
    # Which file the rules came from matters: it is routinely a parent directory (a repo root
    # above the package you are working in), and a user debugging "why was this not blocked"
    # needs to know which file to edit.
    print(f"Policy file       : {source if source else 'none found'}")
    print(f"Sink              : {cfg.get('endpoint') or 'not configured'}")
    budgets = guard.budget_status(policy)
    if policy is None or (not policy.rules and not budgets):
        print("Guardrails        : NONE ARMED. Nothing is being blocked.")
        print("\nRun `pr guard install` to arm "
              f"{', '.join(guard.DEFAULT_PACKS)} and install the hooks.")
        return 0
    use = cfg.get("policy", {}).get("use") if isinstance(cfg.get("policy"), dict) else None
    print(f"Guardrails        : {len(policy.rules)} rules armed"
          f"{' (' + ', '.join(use) + ')' if use else ''}")
    print(f"Policy hash       : {policy.policy_id()[:16]} (committed into every session)")
    if budgets:
        print("\nSpend budgets (estimated, from reported token usage):")
        for b in budgets:
            flag = "OVER" if b["exceeded"] else ("WARN" if b["warning"] else "ok  ")
            print(f"  {flag}  {b['id']:<22} ${b['spent_usd']:,.4f} of ${b['limit_usd']:,.2f} "
                  f"({b['pct']:.0f}%), ${b['remaining_usd']:,.4f} left")
            if not b["prior_known"]:
                # Saying "0% used" for a day budget whose history was never written would be a
                # lie of exactly the kind this feature exists to prevent.
                print("        no cross-run history available, so this figure counts only the "
                      "current run")
        print("  Budgets bind model calls made through the SDK; tool hooks carry no model spend.")
    if pending:
        print(f"\n{len(pending)} decision(s) in the local journal: the sink was unreachable when")
        print(f"they were made, so they are UNSIGNED and are not evidence ({guard.JOURNAL_FILENAME}).")
        print("Start the sink (`pr quickstart`) so later decisions are recorded properly.")
    counts = guard._read_counts_file()
    if counts:
        print(f"\nBlast-radius counters: {len(counts)} session(s) tracked in "
              f"{guard.COUNTS_FILENAME}.")
        print("That file carries `limit` counts across hook processes so a cap actually caps.")
        print("It is local and editable, so it is a convenience, not evidence; deny and")
        print("oversight rules never read it. Clear it with `pr guard reset`.")
    print("\n  pr guard receipt    export the signed record and check what was blocked")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pr", description="Provenrail: tamper-evident agent audit trail.")
    # Not required: a bare `pr` should greet a new user, not print an argparse error (see main()).
    sub = p.add_subparsers(dest="cmd", required=False)

    s = sub.add_parser("serve", help="run the append-only sink")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--db", default="provenrail.db")
    s.add_argument("--anchor", choices=["local", "rfc3161"], default="local")
    s.add_argument("--anchor-interval", type=float, default=60.0,
                   help="seconds between automatic anchors (0 disables)")
    s.add_argument("--tsa", default="https://freetsa.org/tsr")
    s.add_argument("--open", action="store_true",
                   help="run without API-key auth (local/dev only)")
    s.set_defaults(func=_cmd_serve)

    ac = sub.add_parser("activate", help="verify and store a commercial license key")
    ac.add_argument("key", help="your prl_live_ license key from provenrail.com/account")
    ac.set_defaults(func=_cmd_activate)

    d = sub.add_parser("demo", help="run a self-contained demo session and emit a bundle")
    d.add_argument("--out", default="bundle.json")
    d.add_argument("--pin", default="pin.json")
    d.add_argument("--anchor", choices=["local", "rfc3161"], default="local")
    d.add_argument("--tsa", default="https://freetsa.org/tsr")
    d.set_defaults(func=_cmd_demo)

    v = sub.add_parser("verify", help="verify a bundle (trusts nobody)")
    v.add_argument("bundle")
    v.add_argument("--pin")
    v.add_argument("--openings", help="redaction openings keystore, to check disclosed fields")
    v.add_argument("--tlog-pubkey", help="transparency-log public key, to validate the checkpoint "
                   "signature and witness status")
    v.add_argument("--witness-pubkeys", help="comma-separated name=hexpubkey pairs of trusted "
                   "transparency-log witnesses")
    v.add_argument("--registry-pubkey", help="agent identity registry public key")
    v.add_argument("--bitcoin-header", action="append", metavar="HEIGHT=MERKLE_ROOT",
                   help="a trusted Bitcoin header as height=merkle_root_hex (repeatable), to confirm "
                   "an OpenTimestamps proof against the chain")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_verify)

    vc = sub.add_parser("verify-content",
                        help="prove a transcript you hold matches a recorded fingerprint")
    vc.add_argument("bundle")
    vc.add_argument("--file", required=True,
                    help="the content to check (JSON file, or - for stdin); a plain-text file is "
                    "hashed as a JSON string")
    vc.add_argument("--seq", type=int, help="only check the record at this client seq")
    vc.add_argument("--field", help="only check this field (e.g. request, response, args, result)")
    vc.add_argument("--json", action="store_true")
    vc.set_defaults(func=_cmd_verify_content)

    ov = sub.add_parser("ots-verify",
                        help="verify an OpenTimestamps (Bitcoin) proof offline")
    ov.add_argument("proof", help="path to the .ots proof file")
    ov.add_argument("--data-sha256", help="SHA-256 hex of the stamped data (the proof's file digest)")
    ov.add_argument("--block-root", action="append",
                    help="a trusted Bitcoin header as height=merkle_root_hex (repeatable)")
    ov.add_argument("--json", action="store_true")
    ov.set_defaults(func=_cmd_ots_verify)

    dc = sub.add_parser("disclose",
                        help="render a disclosed view of a bundle using an openings keystore")
    dc.add_argument("bundle")
    dc.add_argument("--openings", help="path to the operator-held redaction openings keystore")
    dc.set_defaults(func=_cmd_disclose)

    g = sub.add_parser("guard",
                       help="block destructive coding-agent actions and record the decision")
    g.add_argument("action", nargs="?",
                   choices=["install", "uninstall", "status", "receipt", "reset", "hook"],
                   help="install/uninstall Claude Code hooks, show status, export a receipt, "
                        "or reset the blast-radius counters")
    g.add_argument("--use", help="comma-separated guardrail packs to arm (default: "
                                 "destructive,secrets,production)")
    g.add_argument("--event", choices=["pre", "post"], default="pre",
                   help="hook phase (set by the installed hook command, not by hand)")
    g.add_argument("--out", default="guard-receipt.json", help="receipt bundle path")
    g.set_defaults(func=_cmd_guard)

    rl = sub.add_parser("rules", help="list prebuilt guardrail rules, or check them against a run")
    rl.add_argument("--check", metavar="BUNDLE",
                    help="report which rules would match the tool names in a real run")
    rl.add_argument("--use", help="comma-separated packs/rule ids to check (default: all)")
    rl.add_argument("--verbose", action="store_true", help="show each rule's false-positive note")
    rl.add_argument("--json", action="store_true", help="machine-readable catalogue")
    rl.set_defaults(func=_cmd_rules)

    rk = sub.add_parser("risk", help="list every action a policy blocked in a bundle")
    rk.add_argument("bundle")
    rk.add_argument("--json", action="store_true", help="machine-readable output")
    rk.set_defaults(func=_cmd_risk)

    sp = sub.add_parser("spend", help="estimated spend, per run (from a bundle) or per agent "
                                      "(from the local ledger)")
    sp.add_argument("bundle", nargs="?", help="a run bundle; omit to read the cross-run ledger")
    sp.add_argument("--agent", help="limit the ledger view to one agent id")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.set_defaults(func=_cmd_spend)

    rc = sub.add_parser("reconcile",
                        help="compare recorded estimated spend against a provider invoice CSV")
    rc.add_argument("bundle")
    rc.add_argument("--invoice", required=True, metavar="CSV",
                    help="provider usage or billing export")
    rc.add_argument("--since", metavar="YYYY-MM-DD")
    rc.add_argument("--until", metavar="YYYY-MM-DD")
    rc.add_argument("--json", action="store_true", help="machine-readable output")
    rc.set_defaults(func=_cmd_reconcile)

    r = sub.add_parser("report", help="generate a regulatory attestation from a bundle")
    r.add_argument("bundle")
    r.add_argument("--regime", choices=["eu-ai-act", "hipaa", "generic"], default="generic")
    r.add_argument("--pin")
    r.add_argument("--md", action="store_true", help="render human-readable Markdown")
    r.add_argument("--html", action="store_true",
                   help="render the auditor verification report (printable HTML) instead")
    r.add_argument("--out", help="write the HTML report to this file instead of stdout")
    r.add_argument("--tlog-pubkey", help="transparency-log public key, to verify witness status")
    r.add_argument("--witness-pubkeys", action="append",
                   help="a witness as name=pubkey_hex (repeatable), for the report's witness status")
    r.set_defaults(func=_cmd_report)

    ex = sub.add_parser("export",
                        help="export your own recorded run as a verifiable bundle, then `pr verify` it")
    ex.add_argument("out", nargs="?", default="my-run.json",
                    help="output bundle path (default: my-run.json)")
    ex.add_argument("--stream", help="stream id to export (default: from .provenrail.json)")
    ex.set_defaults(func=_cmd_export)

    k = sub.add_parser("pack", help="build a self-contained evidence pack (zip) for auditors")
    k.add_argument("bundle")
    k.add_argument("--regime", choices=["eu-ai-act", "hipaa", "generic"], default="generic")
    k.add_argument("--pin")
    k.add_argument("--out", default="evidence.zip")
    k.set_defaults(func=_cmd_pack)

    df = sub.add_parser("diff", help="diff two run bundles with provable fidelity")
    df.add_argument("bundle_a")
    df.add_argument("bundle_b")
    df.add_argument("--json", action="store_true")
    df.set_defaults(func=_cmd_diff)

    q = sub.add_parser("quickstart",
                       help="one command to a working setup: start a sink + write config")
    q.add_argument("--url", help="provision against an existing sink at this URL instead of "
                   "starting a local one")
    q.add_argument("--account-key", help="account API key, if the target sink requires accounts")
    q.add_argument("--label", default="my-agent")
    q.add_argument("--port", type=int, default=8000)
    q.add_argument("--db", default="provenrail.db")
    q.add_argument("--anchor", choices=["local", "rfc3161"], default="local")
    q.add_argument("--stop", action="store_true", help="stop the local sink started earlier")
    q.set_defaults(func=_cmd_quickstart)

    w = sub.add_parser("witness", help="run a standalone out-of-process C2SP witness")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8744)
    w.add_argument("--db", default="witness.db", help="durable witness state (key + seen sizes)")
    w.add_argument("--name", default="witness", help="this witness's C2SP name")
    w.add_argument("--log", action="append",
                   help="pin a log this witness will cosign, as origin=pubkey_hex (repeatable)")
    w.set_defaults(func=_cmd_witness)

    sc = sub.add_parser("sidecar",
                        help="run the out-of-process capture proxy in front of a model API")
    sc.add_argument("--upstream", default="https://api.openai.com",
                    help="real provider base URL to forward to")
    sc.add_argument("--provider", help="provider label (inferred from --upstream if omitted)")
    sc.add_argument("--host", default="127.0.0.1")
    sc.add_argument("--port", type=int, default=8788)
    sc.add_argument("--label", default="sidecar", help="stream label for the recorded session")
    sc.add_argument("--fail-closed", action="store_true",
                    help="refuse (502) a call that cannot be recorded instead of forwarding it")
    sc.set_defaults(func=_cmd_sidecar)
    return p


def _print_welcome() -> None:
    """A bare `pr` is usually a new user looking around. Greet them with the one command worth
    running first and where to go next, instead of an argparse 'arguments are required' error."""
    print("Provenrail: a tamper-evident, independently verifiable record of what your AI agent did.")
    print()
    print("Start here (no account, nothing leaves your machine):")
    print("  pr demo            create a sample sealed run")
    print("  pr verify bundle.json   re-derive every hash and signature, trusting nobody")
    print()
    print("Record your own agent:")
    print("  pr quickstart      start a local recorder, then `import provenrail as fr`")
    print()
    print("Block risky actions, not just record them:")
    print("  pr guard install   stop your coding agent deleting things (Claude Code hooks)")
    print("  pr rules           prebuilt guardrail packs (destructive, secrets, money, ...)")
    print()
    print("Full walkthrough: https://provenrail.com/start     All commands: pr -h")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not hasattr(args, "func"):
        _print_welcome()
        return 0
    try:
        return args.func(args)
    except FileNotFoundError as e:
        # A first-time user following /start may mistype a filename. Show the path, not a traceback.
        print(f"file not found: {e.filename}", file=sys.stderr)
        print("Check the name and that you are in the right folder (`ls` lists files here).",
              file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        # The /start guide tells beginners to hand-edit a bundle to feel tamper detection; a
        # stray character makes it invalid JSON. That is a malformed file, not tampering, so
        # say so plainly instead of dumping a Python traceback.
        print(f"that file is not valid JSON ({e.msg} at line {e.lineno}).", file=sys.stderr)
        print("If you edited it by hand, a stray character can break the format. Re-export it, "
              "or run `pr demo` for a fresh bundle.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
