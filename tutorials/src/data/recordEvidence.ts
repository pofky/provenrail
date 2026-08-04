import { Step } from "../lib";

export const eyebrow = "Tutorial 04";
export const title = "Record from code + evidence";

export const steps: Step[] = [
  {
    caption: "Record from Python",
    note: "Two lines wrap your agent. Model and tool calls are captured automatically.",
    lines: [
      { kind: "cmd", text: "cat agent.py" },
      { kind: "out", text: "import provenrail as fr", tone: "accent" },
      { kind: "out", text: "", tone: "dim" },
      { kind: "out", text: 'with fr.record("support-bot") as run:', tone: "accent" },
      { kind: "out", text: "    answer = client.chat.completions.create(...)   # captured", tone: "dim" },
      { kind: "out", text: '    run.record_decision("refund approved", amount=20)', tone: "accent" },
      { kind: "cmd", text: "python agent.py      # sealed + drained off-box to your sink" },
    ],
  },
  {
    caption: "Same capture in TypeScript",
    note: "Node 20+. A TS-recorded run is byte-for-byte verifiable by the same tools.",
    lines: [
      { kind: "cmd", text: "npm install provenrail" },
      { kind: "cmd", text: "cat agent.ts" },
      { kind: "out", text: 'import { record } from "provenrail";', tone: "accent" },
      { kind: "out", text: "", tone: "dim" },
      { kind: "out", text: 'await record("support-bot", async (pr) => {', tone: "accent" },
      { kind: "out", text: '  await pr.recordModelCall("openai", "gpt-5", { prompt }, out);', tone: "accent" },
      { kind: "out", text: "});", tone: "accent" },
    ],
  },
  {
    caption: "Turn a run into an audit report",
    note: "Map a verified run to a regulatory regime (EU AI Act, HIPAA). Team plan.",
    lines: [
      { kind: "cmd", text: "pr report --regime eu-ai-act bundle.json --md" },
      { kind: "out", text: "# Provenrail evidence record: eu-ai-act", tone: "accent" },
      { kind: "out", text: "Integrity verified: YES", tone: "ok" },
      { kind: "out", text: "Records: 6  |  Anchors: 1  |  model_call: 1, decision: 1, human_oversight: 1", tone: "default" },
    ],
  },
  {
    caption: "Package the evidence",
    note: "One zip an auditor can open and verify themselves, offline.",
    lines: [
      { kind: "cmd", text: "pr pack bundle.json --pin pin.json" },
      { kind: "out", text: "Wrote 14357 byte evidence pack to evidence.zip", tone: "ok" },
      { kind: "out", text: "Contents: bundle.json, attestation, VERIFY.txt, MANIFEST.json, pin.json", tone: "dim" },
    ],
  },
];
