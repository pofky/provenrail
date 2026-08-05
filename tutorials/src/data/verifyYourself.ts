import { Step } from "../lib";

export const eyebrow = "Tutorial 02";
export const title = "Verify it yourself";

export const steps: Step[] = [
  {
    caption: "Generate a recorded run",
    note: "A real session with a dual hash chain, trusted-time anchor, and transparency log.",
    lines: [
      { kind: "cmd", text: "pr demo" },
      { kind: "out", text: "Recorded 6 events to bundle.json", tone: "default" },
      { kind: "out", text: "Client pin written to pin.json", tone: "default" },
    ],
  },
  {
    caption: "Verify against an independent witness",
    note: "The transparency-log witness is a third party that co-signs. This is the strongest proof.",
    lines: [
      { kind: "cmd", text: "pr verify bundle.json --tlog-pubkey <log> --witness-pubkeys demo-witness=<key>" },
      { kind: "out", text: "[info] tlog_cosig_valid: anchor 0: witness 'demo-witness' cosignature valid", tone: "info" },
      { kind: "out", text: "[info] tlog_inclusion_witnessed_ok: in the transparency log, witnessed by 1 party", tone: "info" },
      { kind: "out", text: "[info] scitt_receipt_ok: 1 SCITT COSE receipt verified against the service", tone: "info" },
      { kind: "blank" },
      { kind: "out", text: "RESULT: VERIFIED", tone: "ok" },
    ],
  },
  {
    caption: "Now tamper with one byte",
    note: "Edit the bundle after the fact, exactly what a bad actor would try.",
    lines: [
      { kind: "cmd", text: "vi bundle.json      # change one character, then save" },
      { kind: "cmd", text: "pr verify bundle.json --pin pin.json" },
      { kind: "out", text: "[FAIL] recv_hash_mismatch: recv_seq 0: stored record bytes do not match recv_hash", tone: "err" },
      { kind: "out", text: "[FAIL] client_hash_mismatch: seq=0: record_hash does not match content", tone: "err" },
      { kind: "blank" },
      { kind: "out", text: "RESULT: TAMPERING DETECTED", tone: "err" },
    ],
  },
  {
    caption: "CI-ready: it exits non-zero",
    note: "Wire pr verify into a pipeline. Trust the math, never the agent or the vendor.",
    lines: [
      { kind: "cmd", text: "echo $?" },
      { kind: "out", text: "1", tone: "err" },
    ],
  },
];
