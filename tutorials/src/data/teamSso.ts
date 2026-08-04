import { Step } from "../lib";

// Tutorial 05: Team & SSO. Every command and response below is the real shape returned by
// provenrail 0.2.0 (captured from the members + SSO endpoints), abbreviated only by truncating ids.
export const eyebrow = "Tutorial 05";
export const title = "Team & SSO";

export const steps: Step[] = [
  {
    caption: "Invite your team",
    note: "Team plan: up to 10 members, each with their own key and role.",
    lines: [
      { kind: "cmd", text: "curl -X POST $URL/v1/members -d '{\"role\":\"admin\"}'" },
      { kind: "out", text: "{", tone: "dim" },
      { kind: "out", text: "  \"member_id\": \"mbr_9cf5...\",", tone: "default" },
      { kind: "out", text: "  \"role\": \"admin\",", tone: "default" },
      { kind: "out", text: "  \"api_key\": \"pr_mk_rPk8...\"     # shown once, store it", tone: "ok" },
      { kind: "out", text: "}", tone: "dim" },
    ],
  },
  {
    caption: "Roles are least-privilege",
    note: "owner / admin / member / viewer. You can only grant a role at or below your own.",
    lines: [
      { kind: "cmd", text: "curl -X POST $URL/v1/agents  -H \"Bearer $VIEWER_KEY\"" },
      { kind: "out", text: "{", tone: "dim" },
      { kind: "out", text: "  \"detail\": \"role 'viewer' lacks permission 'agent.manage'\"", tone: "err" },
      { kind: "out", text: "}                                       # 403 Forbidden", tone: "err" },
    ],
  },
  {
    caption: "Connect your IdP once",
    note: "Pin your OIDC issuer, audience and JWKS. Your staff never get a second password.",
    lines: [
      { kind: "cmd", text: "curl -X PUT $URL/v1/sso/config -d @okta.json" },
      { kind: "out", text: "{", tone: "dim" },
      { kind: "out", text: "  \"configured\": true,", tone: "ok" },
      { kind: "out", text: "  \"issuer\": \"https://acme.okta.com\",", tone: "default" },
      { kind: "out", text: "  \"default_role\": \"member\"", tone: "default" },
      { kind: "out", text: "}", tone: "dim" },
    ],
  },
  {
    caption: "Staff sign in with your IdP",
    note: "They present an ID token; Provenrail validates it offline and provisions them just-in-time.",
    lines: [
      { kind: "cmd", text: "curl -X POST $URL/v1/sso/login -d '{\"id_token\":\"eyJ...\"}'" },
      { kind: "out", text: "{", tone: "dim" },
      { kind: "out", text: "  \"member_id\": \"mbr_9ca5...\",", tone: "default" },
      { kind: "out", text: "  \"role\": \"member\",          # JIT-provisioned at default role", tone: "ok" },
      { kind: "out", text: "  \"api_key\": \"pr_mk_lAFz...\"", tone: "default" },
      { kind: "out", text: "}", tone: "dim" },
    ],
  },
  {
    caption: "Forged tokens never get in",
    note: "Only RS256 and EdDSA. alg:none, HMAC confusion and a wrong issuer or audience are all rejected.",
    lines: [
      { kind: "cmd", text: "curl -X POST $URL/v1/sso/login -d '{\"id_token\":\"<alg:none>\"}'" },
      { kind: "out", text: "{", tone: "dim" },
      { kind: "out", text: "  \"detail\": \"SSO rejected: algorithm 'none' is not allowed\"", tone: "err" },
      { kind: "out", text: "}                                       # 401 Unauthorized", tone: "err" },
    ],
  },
  {
    caption: "Your team, on the audit trail",
    note: "Every invite, login and export lands in a tamper-evident, hash-chained access log.",
    lines: [
      { kind: "cmd", text: "curl $URL/v1/members" },
      { kind: "out", text: "dana@acme.com      admin    active", tone: "default" },
      { kind: "out", text: "jordan@acme.com    member   active   (via SSO)", tone: "default" },
      { kind: "blank" },
      { kind: "out", text: "RESULT: TEAM PROVISIONED", tone: "ok" },
    ],
  },
];
