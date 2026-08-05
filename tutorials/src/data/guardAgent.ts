import { Step } from "../lib";

// Every line below is copied verbatim from a real 0.2.13 session: install, arm, three hook
// invocations against a live sink, receipt, verify. Nothing is mocked or prettified, which is
// the whole point of the claim on the site.

export const eyebrow = "Start here";
export const title = "Guard a coding agent";

export const steps: Step[] = [
  {
    caption: "Arm the guardrails",
    note: "Two commands. No SDK, no code change, no account.",
    lines: [
      { kind: "cmd", text: "uv tool install provenrail" },
      { kind: "cmd", text: "pr quickstart && pr guard install" },
      { kind: "out", text: "started a local sink (pid 44678) and wrote .provenrail.json", tone: "info" },
      { kind: "out", text: "Armed guardrails in .provenrail.json: destructive, secrets, production, access", tone: "ok" },
      { kind: "out", text: "Installed Claude Code hooks in .claude/settings.json", tone: "ok" },
    ],
  },
  {
    caption: "The agent tries to delete your work",
    note: "Blocked at the tool boundary, before the command runs. The model does not get a vote.",
    lines: [
      { kind: "cmd", text: "rm -rf /var/data" },
      { kind: "out", text: "deny", tone: "err" },
      { kind: "out", text: "Provenrail guardrail destructive.recursive-force-remove:", tone: "err" },
      { kind: "out", text: "argument contains a recursive delete", tone: "dim" },
      { kind: "blank" },
      { kind: "cmd", text: "terraform destroy -auto-approve" },
      { kind: "out", text: "deny", tone: "err" },
      { kind: "out", text: "Provenrail guardrail production.terraform-destroy", tone: "err" },
    ],
  },
  {
    caption: "A decision for a human stays a human decision",
    note: "Reading .env is sometimes legitimate, so you are asked. Your answer is recorded as oversight.",
    lines: [
      { kind: "cmd", text: "read .env" },
      { kind: "out", text: "ask", tone: "accent" },
      { kind: "out", text: "Provenrail guardrail secrets.env-file-read: action touches a .env file", tone: "default" },
      { kind: "out", text: "(approve here and the approval is recorded as human oversight)", tone: "dim" },
    ],
  },
  {
    caption: "The block is evidence, not a log line",
    note: "Every decision is Ed25519 signed and hash-chained off-box as it happens.",
    lines: [
      { kind: "cmd", text: "pr guard receipt" },
      { kind: "out", text: "wrote guard-receipt.json (15 records, 1 anchors)", tone: "info" },
      { kind: "blank" },
      { kind: "out", text: "Policy decisions: 3 (0 allowed, 2 DENIED, 1 escalated to a human)", tone: "default" },
      { kind: "out", text: "  DENIED  tool_call Bash", tone: "err" },
      { kind: "out", text: "          rule=destructive.recursive-force-remove", tone: "dim" },
      { kind: "out", text: "  DENIED  tool_call Bash", tone: "err" },
      { kind: "out", text: "          rule=production.terraform-destroy", tone: "dim" },
    ],
  },
  {
    caption: "Check it yourself, trusting nobody",
    note: "The verifier recomputes every hash and signature locally. Change one byte and it fails.",
    lines: [
      { kind: "cmd", text: "pr verify guard-receipt.json" },
      { kind: "out", text: "[info] policy_verified: committed policy cbddcd9112df verified", tone: "info" },
      { kind: "out", text: "[info] summary: 15 records, 1 anchors, 0 heartbeats.", tone: "info" },
      { kind: "blank" },
      { kind: "out", text: "RESULT: VERIFIED", tone: "ok" },
    ],
  },
];
