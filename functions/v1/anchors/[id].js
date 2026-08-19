// GET /v1/anchors/{id}, on provenrail.com.
//
// This is the link a customer hands an auditor, so it has to work for the person least equipped
// to read JSON: no account, no login, no tooling, opened in whatever browser they have. It is
// rendered here at the edge rather than in the browser so it also works with JavaScript off and
// so the page is complete on first paint.
//
// The wording below is deliberately the same as the page the self-hosted sink serves
// (src/provenrail/server/app.py:_render_anchor_page). An auditor may be shown either one and must
// be told the same thing about what an anchor does and does not prove.
// tests/test_anchor_page_lockstep.py holds the two together.
import { SUPABASE_FUNCTIONS } from "../../_supabase.js";

const UPSTREAM = `${SUPABASE_FUNCTIONS}/anchor`;

const CSS = `
  :root{color-scheme:light dark;--bg:#0b0a08;--fg:#f3f5f7;--mid:#99a2af;--line:#29221a;
        --ok:#6fcf86;--warn:#e0b040;--card:#12100c}
  @media(prefers-color-scheme:light){:root{--bg:#fdfbf7;--fg:#0c0f14;--mid:#515b67;
        --line:#e9e2d5;--ok:#1f7038;--warn:#7e6428;--card:#f6f3ed}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,sans-serif;
       padding:2rem 1.1rem}
  main{max-width:44rem;margin:0 auto}
  h1{font-size:1.5rem;line-height:1.25;margin:0 0 .4rem}
  .lede{color:var(--mid);margin:0 0 1.6rem}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem 1.1rem;
        margin-bottom:1rem}
  .k{color:var(--mid);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}
  .v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;font-size:.92rem}
  ul{margin:.4rem 0 0;padding-left:1.1rem}li{margin-bottom:.45rem;color:var(--mid)}
  li strong{color:var(--fg)}
  .h-ok{color:var(--ok);font-weight:600}.h-warn{color:var(--warn);font-weight:600}
  a{color:inherit}
  footer{color:var(--mid);font-size:.85rem;margin-top:2rem;border-top:1px solid var(--line);
         padding-top:1rem}
`;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function wantsHtml(request) {
  return (request.headers.get("accept") || "").includes("text/html");
}

function missingPage(id) {
  return `<!doctype html><meta charset=utf-8><title>No such anchor record</title>
<meta name=viewport content='width=device-width,initial-scale=1'>
<style>${CSS}</style><main><h1>No anchor record with that id</h1>
<p class=lede>Nothing here has been published under <code>${esc(id)}</code>. Check the link you
were given: an id that does not resolve is not evidence of anything, in either direction.</p>
</main>`;
}

function page(a) {
  const receipt = a.receipt || {};
  const independent = receipt.kind === "rfc3161";
  const timeLine = independent
    ? `<span class='h-ok'>Independently timestamped.</span> The time below was signed by
       ${esc(receipt.tsa_url)}, a third-party timestamping authority, so it cannot have been
       back-dated by the customer or by us.`
    : `<span class='h-warn'>Self-asserted time.</span> This record was signed with our own key
       against our own clock, not by an independent timestamping authority. It proves the root
       was published here, in this order, relative to the other records in this stream. It is
       not independent proof of the calendar date.`;

  return `<!doctype html><html lang=en><meta charset=utf-8>
<title>Anchor record ${esc(a.anchor_id)}</title>
<meta name=viewport content='width=device-width,initial-scale=1'>
<meta name=robots content='noindex'>
<style>${CSS}</style>
<main>
  <h1>Anchor record</h1>
  <p class=lede>Someone gave you this link so you could check their claim without taking their
  word for it, and without an account here.</p>

  <div class=card>
    <div class=k>Fingerprint of their records</div>
    <div class=v>${esc(a.merkle_root)}</div>
  </div>
  <div class=card>
    <div class=k>Covers</div>
    <div class=v>${esc(a.covers_up_to)} records</div>
  </div>
  <div class=card>
    <div class=k>Published here at</div>
    <div class=v>${esc(receipt.gen_time || "unknown")}</div>
  </div>

  <div class=card>
    <div class=k>What this record proves</div>
    <ul>
      <li>${timeLine}</li>
      <li><strong>It cannot be changed after the fact.</strong> Coverage of a stream can only
      grow here. We refuse to publish a shorter history for a stream than one already published,
      and we refuse two different fingerprints for the same length.</li>
      <li><strong>We never received their records.</strong> Only the fingerprint above and the
      count. There is no field in the request their data could have travelled in, so we cannot
      show it to you, and we could not have altered it.</li>
    </ul>
  </div>

  <div class=card>
    <div class=k>What this record does not prove</div>
    <ul>
      <li><strong>That they recorded everything.</strong> This shows that what they recorded has
      not been altered. It cannot show that an action was never written down in the first place.
      No record of this kind can.</li>
      <li><strong>That the records say what they told you.</strong> Ask them for the records
      themselves, then check the fingerprint matches.</li>
    </ul>
  </div>

  <div class=card>
    <div class=k>How to check it yourself</div>
    <ul>
      <li>Ask them for their exported bundle file.</li>
      <li>Run <code>pr anchor-verify bundle.json receipt.json</code>. It recomputes the
      fingerprint from their records and compares it with the one above, offline, without asking
      us anything.</li>
      <li>If the two do not match, the records you were shown are not the records that were
      published here.</li>
    </ul>
  </div>

  <footer>Machine-readable version of this page: add <code>Accept: application/json</code>.
  Provenrail is evidence tooling. It is not legal advice, a compliance guarantee, or an audit
  opinion.</footer>
</main></html>`;
}

function html(body, status) {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html;charset=utf-8", "x-robots-tag": "noindex" },
  });
}

export async function onRequest(context) {
  const { request, params } = context;
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response(JSON.stringify({ error: "read only; POST a new anchor to /v1/anchors" }),
      { status: 405, headers: { "content-type": "application/json" } });
  }
  const id = String(params.id || "");
  let upstream;
  try {
    upstream = await fetch(`${UPSTREAM}?id=${encodeURIComponent(id)}`);
  } catch (_e) {
    const msg = "the anchor service is unreachable, so this record cannot be shown right now. " +
      "That is not a finding about the record.";
    return wantsHtml(request)
      ? html(`<!doctype html><meta charset=utf-8><title>Temporarily unavailable</title>
<style>${CSS}</style><main><h1>Temporarily unavailable</h1><p class=lede>${msg}</p></main>`, 502)
      : new Response(JSON.stringify({ error: msg }), { status: 502, headers: { "content-type": "application/json" } });
  }

  const text = await upstream.text();
  if (!wantsHtml(request)) {
    return new Response(text, {
      status: upstream.status,
      headers: { "content-type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }
  if (upstream.status === 404) return html(missingPage(id), 404);
  if (!upstream.ok) return html(missingPage(id), upstream.status);
  let data;
  try {
    data = JSON.parse(text);
  } catch (_e) {
    return html(missingPage(id), 502);
  }
  return html(page(data), 200);
}
