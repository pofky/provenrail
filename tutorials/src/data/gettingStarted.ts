import { Step } from "../lib";

export const eyebrow = "Tutorial 01";
export const title = "Getting started";

export const steps: Step[] = [
  {
    caption: "Install Provenrail",
    note: "One pip install. Works on Python 3.11+, no account needed.",
    lines: [
      { kind: "cmd", text: "pip install provenrail" },
      { kind: "out", text: "Successfully installed provenrail-0.2.0", tone: "ok" },
    ],
  },
  {
    caption: "Start a local sink",
    note: "Provisions keys and config for you. No tokens to copy and paste.",
    lines: [
      { kind: "cmd", text: "pr quickstart" },
      { kind: "out", text: "started a local sink (pid 64447) and wrote .provenrail.json", tone: "info" },
      { kind: "blank" },
      { kind: "out", text: "Now your whole setup is two lines:", tone: "dim" },
      { kind: "out", text: "    import provenrail as fr", tone: "accent" },
      { kind: "out", text: "    with fr.record('my-agent'):", tone: "accent" },
      { kind: "out", text: "        ...   # your agent runs; calls are captured automatically", tone: "dim" },
    ],
  },
  {
    caption: "Record and chain a run",
    note: "pr demo runs a real session, hash-chains every event, and writes a bundle.",
    lines: [
      { kind: "cmd", text: "pr demo" },
      { kind: "out", text: "Recorded 6 events to bundle.json", tone: "default" },
      { kind: "out", text: "Client pin written to pin.json", tone: "default" },
      { kind: "out", text: "Share token (read-only proof page): /share/pr_share_cRA1YX5Az4...", tone: "dim" },
    ],
  },
  {
    caption: "Verify it, trusting nobody",
    note: "Recomputes the hash chain and every signature offline. Exit 0 means intact.",
    lines: [
      { kind: "cmd", text: "pr verify bundle.json --pin pin.json" },
      { kind: "out", text: "[info] pin_ok: client pin confirmed: sink holds the record set up to recv_seq 5", tone: "info" },
      { kind: "out", text: "[info] summary: 6 records, 1 anchors, 0 heartbeats.", tone: "info" },
      { kind: "blank" },
      { kind: "out", text: "RESULT: VERIFIED", tone: "ok" },
    ],
  },
];
