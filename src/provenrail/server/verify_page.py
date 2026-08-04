"""Public hosted verifier page.

Anyone, with no install and no account, can drop a Provenrail bundle here and get the
full standalone-verifier result: every hash, signature, chain link, Merkle root, and RFC 3161
timestamp recomputed server-side. It reinforces the core promise, that the record is
verifiable without trusting the agent, the sink, or us, and gives auditors a zero-friction
way to check evidence. The same verifier runs in the CLI (`pr verify`); this is a convenience
surface, not a separate trust root.
"""

from __future__ import annotations

VERIFY_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Verify a record | Provenrail</title>
<meta name="description" content="Independently verify a Provenrail bundle. Every hash, signature, chain link, Merkle root, and timestamp is recomputed. Trust neither the agent nor the sink.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0b0e;--bg-2:#0f1115;--bg-3:#14171c;--border:#20242c;--border-hi:#2e333d;
--accent:#2ee6a6;--accent-dim:#16c489;--accent-ink:#04130d;--accent-glow:rgba(46,230,166,.16);
--text-hi:#f3f5f7;--text-mid:#99a2af;--text-lo:#5a626e;--text-mono:#c9d0d9;
--green:#2ee6a6;--green-glow:rgba(46,230,166,.14);--red:#f06a5d;--red-glow:rgba(240,106,93,.14);
--amber:#f0b23a;--amber-glow:rgba(240,178,58,.14);--blue:#2ee6a6;
--font-mono:'DM Mono','Fira Code',ui-monospace,monospace;--font-body:'DM Sans',system-ui,-apple-system,sans-serif;
--r-sm:4px;--r-md:8px;--r-lg:12px;--r-xl:18px;--gutter:clamp(1rem,5vw,2.5rem)}
@media(prefers-color-scheme:light){:root{--bg:#fbfcfd;--bg-2:#f5f7f9;--bg-3:#ffffff;--border:#e4e8ee;--border-hi:#d2d8e0;--accent:#07a06a;--accent-dim:#058a5b;--accent-ink:#ffffff;--green:#07a06a;--green-glow:rgba(7,160,106,.14);--text-hi:#0c0f14;--text-mid:#515b67;--text-lo:#97a0ab;--text-mono:#1b2430}}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font-body);line-height:1.55;color:var(--text-hi);background:var(--bg);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.5;
background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='0.035'/%3E%3C/svg%3E")}
.wrap{position:relative;z-index:1;max-width:760px;margin:0 auto;padding:clamp(2rem,7vw,4.5rem) var(--gutter) 5rem}
.eyebrow{font-family:var(--font-mono);font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);display:flex;align-items:center;gap:.5rem;margin-bottom:1rem}
.eyebrow::before{content:'';width:18px;height:1px;background:var(--accent)}
h1{font-family:var(--font-mono);font-size:clamp(1.7rem,4vw,2.4rem);font-weight:500;letter-spacing:-.02em;line-height:1.12;margin-bottom:.85rem}
.lede{color:var(--text-mid);font-size:1rem;max-width:58ch;margin-bottom:2.25rem}
a{color:var(--accent)}
.drop{border:1.5px dashed var(--border-hi);border-radius:var(--r-xl);background:var(--bg-2);padding:clamp(2rem,6vw,3.25rem);text-align:center;transition:border-color .18s,background .18s;cursor:pointer}
.drop.over{border-color:var(--accent);background:var(--accent-glow)}
.drop .ic{width:44px;height:44px;margin:0 auto 1rem;color:var(--accent)}
.drop .t{font-family:var(--font-mono);font-size:.95rem;color:var(--text-hi);margin-bottom:.4rem}
.drop .d{font-size:.85rem;color:var(--text-lo)}
.drop .or{margin:1.1rem 0 .3rem;font-family:var(--font-mono);font-size:.72rem;color:var(--text-lo)}
.btn{display:inline-flex;align-items:center;gap:.5rem;font-size:.88rem;font-weight:600;background:var(--accent);color:var(--accent-ink);border:none;border-radius:var(--r-md);padding:.7rem 1.3rem;min-height:46px;cursor:pointer;transition:background .15s,transform .12s}
.btn:hover{background:var(--accent-dim);transform:translateY(-1px)}
.btn.ghost{background:transparent;color:var(--text-hi);border:1px solid var(--border-hi);font-weight:500}
.btn.ghost:hover{border-color:var(--accent)}
.paste{margin-top:1.25rem}
.paste summary{font-family:var(--font-mono);font-size:.8rem;color:var(--text-mid);cursor:pointer;list-style:none;display:flex;align-items:center;gap:.4rem}
.paste summary::-webkit-details-marker{display:none}
.paste summary::before{content:'+';color:var(--accent);font-weight:600}
.paste[open] summary::before{content:'-'}
textarea{width:100%;margin-top:.75rem;min-height:140px;font-family:var(--font-mono);font-size:.78rem;color:var(--text-mono);background:var(--bg);border:1px solid var(--border);border-radius:var(--r-md);padding:.8rem;resize:vertical}
textarea:focus{outline:none;border-color:var(--accent)}
.result{margin-top:2rem}
.verdict{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;border:1px solid var(--border);border-left-width:3px;border-radius:var(--r-md);padding:1.15rem 1.3rem;background:var(--bg-2)}
.verdict.verified{border-left-color:var(--green)}.verdict.amber{border-left-color:var(--amber)}
.verdict.tampered{border-left-color:var(--red)}.verdict.error{border-left-color:var(--text-lo)}
.vbadge{display:inline-flex;align-items:center;gap:.5rem;font-family:var(--font-mono);font-size:.82rem;font-weight:500;padding:.4rem .75rem;border-radius:999px;border:1px solid;white-space:nowrap}
.vbadge .bd{width:8px;height:8px;border-radius:50%}
.verified .vbadge{color:var(--green);border-color:color-mix(in srgb,var(--green) 45%,transparent);background:var(--green-glow)}.verified .vbadge .bd{background:var(--green)}
.amber .vbadge{color:var(--amber);border-color:color-mix(in srgb,var(--amber) 45%,transparent);background:var(--amber-glow)}.amber .vbadge .bd{background:var(--amber)}
.tampered .vbadge{color:var(--red);border-color:color-mix(in srgb,var(--red) 45%,transparent);background:var(--red-glow)}.tampered .vbadge .bd{background:var(--red)}
.error .vbadge{color:var(--text-lo);border-color:var(--border)}.error .vbadge .bd{background:var(--text-lo)}
.vmeta{flex:1;min-width:12rem}
.vmeta .h{font-family:var(--font-mono);font-size:1.02rem;color:var(--text-hi)}
.vmeta .s{font-size:.84rem;color:var(--text-mid);margin-top:.2rem}
.findings{margin-top:1.25rem;border:1px solid var(--border);border-radius:var(--r-lg);overflow:hidden}
.fhead{padding:.8rem 1.1rem;background:var(--bg-3);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:.74rem;letter-spacing:.06em;text-transform:uppercase;color:var(--text-mid);display:flex;gap:1rem}
.fhead .ct{color:var(--text-lo)}
.f{display:flex;gap:.85rem;align-items:flex-start;padding:.7rem 1.1rem;border-bottom:1px solid var(--border)}
.f:last-child{border-bottom:0}
.f .sev{font-family:var(--font-mono);font-size:.64rem;font-weight:500;letter-spacing:.06em;text-transform:uppercase;padding:.18rem .45rem;border-radius:var(--r-sm);flex-shrink:0;margin-top:.1rem}
.f.fail .sev{color:var(--red);background:var(--red-glow)}.f.warn .sev{color:var(--amber);background:var(--amber-glow)}.f.info .sev{color:var(--blue);background:rgba(46,230,166,.12)}
.f .fc{min-width:0}
.f .code{font-family:var(--font-mono);font-size:.78rem;color:var(--text-hi)}
.f .detail{font-size:.82rem;color:var(--text-mid);margin-top:.15rem;word-break:break-word}
.again{margin-top:1.5rem;display:flex;gap:.6rem;flex-wrap:wrap}
.foot{margin-top:2.5rem;font-size:.82rem;color:var(--text-lo);line-height:1.6;border-top:1px solid var(--border);padding-top:1.25rem}
.foot code{font-family:var(--font-mono);background:var(--bg-3);padding:.1em .4em;border-radius:var(--r-sm);color:var(--text-mono)}
.spin{width:18px;height:18px;border:2px solid var(--border-hi);border-top-color:var(--accent);border-radius:50%;animation:sp .7s linear infinite;display:inline-block}
@keyframes sp{to{transform:rotate(360deg)}}
.checks{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1.1rem}
.check{display:inline-flex;align-items:center;gap:.45rem;font-family:var(--font-mono);font-size:.72rem;padding:.34rem .65rem;border-radius:999px;border:1px solid var(--border);color:var(--text-lo);background:var(--bg-2);white-space:nowrap}
.check .ck{width:13px;height:13px;flex-shrink:0}
.check.on{color:var(--green);border-color:color-mix(in srgb,var(--green) 35%,transparent)}
.check.off{color:var(--text-lo);opacity:.7}
.redact{margin-top:1.25rem;border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:var(--r-lg);padding:1.05rem 1.2rem;background:var(--bg-2)}
.redact .rt{font-family:var(--font-mono);font-size:.84rem;color:var(--text-hi);display:flex;align-items:center;gap:.5rem;margin-bottom:.35rem}
.redact .rt svg{width:16px;height:16px;color:var(--accent)}
.redact .rd{font-size:.84rem;color:var(--text-mid);line-height:1.55}
.redact .rhint{margin-top:.7rem;font-size:.8rem;color:var(--text-lo)}
.redact .rhint b{color:var(--text-mid);font-weight:500}
.fade{animation:fadein .35s ease}
@keyframes fadein{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@media(max-width:520px){
  .verdict{flex-direction:column;align-items:flex-start;gap:.7rem}
  .vmeta{min-width:0}
  .vbadge{max-width:100%}
  .fhead{flex-wrap:wrap;gap:.3rem 1rem}
}
.hidden{display:none}
</style>
</head>
<body>
<main class="wrap">
  <div class="eyebrow">Independent verification</div>
  <h1>Verify a record</h1>
  <p class="lede">Drop a Provenrail bundle and the standalone verifier recomputes every hash, signature, chain link, Merkle root, and RFC 3161 timestamp from scratch. It trusts neither the agent that produced the record nor the sink that stored it. This page is a convenience; the same check runs offline in <code style="font-family:var(--font-mono)">pr verify</code>.</p>

  <div id="drop" class="drop" tabindex="0" role="button" aria-label="Upload a bundle JSON file">
    <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
    <div class="t">Drop bundle.json here</div>
    <div class="d">or choose a file to verify, nothing is uploaded for storage</div>
    <div class="or">also accepts an optional pin.json or openings.json</div>
    <button class="btn" id="pick" type="button">Choose file</button>
    <input id="file" type="file" accept="application/json,.json" multiple class="hidden">
  </div>

  <details class="paste">
    <summary>Paste bundle JSON instead</summary>
    <textarea id="ta" placeholder='{"format":"flightrecorder.bundle/1", ...}' spellcheck="false"></textarea>
    <div style="margin-top:.6rem"><button class="btn ghost" id="verifyPaste" type="button">Verify pasted JSON</button></div>
  </details>

  <div id="result" class="result hidden"></div>

  <div class="foot">
    Prefer your own machine? <code>pip install provenrail</code> then <code>pr verify bundle.json --pin pin.json</code>. The verifier is open source and the evidence format is specified in <code>SPEC.md</code>, so anyone can build an independent implementation. Completeness, that nothing was withheld before being recorded, is never claimed by this tool.
  </div>
</main>

<script>
const $=s=>document.querySelector(s);
let pin=null, bundle=null, openings=null;
const drop=$('#drop'), result=$('#result');
const CHECK='<svg class="ck" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
const DOT='<svg class="ck" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>';

function show(html){ result.className='result fade'; result.classList.remove('hidden'); result.innerHTML=html; result.scrollIntoView({behavior:'smooth',block:'nearest'}); }
function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function classify(rep){
  if(!rep.ok) return {st:'tampered',head:'Tampering detected',sub:rep.fail+' integrity failure(s). This record set has been altered, reordered, or truncated.',badge:'Tampering detected'};
  const codes=new Set((rep.findings||[]).map(f=>f.code));
  if(codes.has('anchor_rfc3161_unchecked')) return {st:'amber',head:'Integrity verified, timestamp not validated here',sub:'The chains and signatures are valid with no tampering. An RFC 3161 trusted timestamp is present but its CMS signature was not validated in the browser. Run pr verify (or the server verifier) for full timestamp validation.',badge:'Verified, timestamp unchecked'};
  if(codes.has('local_anchor_only')||codes.has('no_anchor')) return {st:'amber',head:'Integrity verified, no trusted timestamp',sub:'Every record is signed and chained with no detected tampering, but no third-party RFC 3161 timestamp covers them.',badge:'Verified, no timestamp'};
  return {st:'verified',head:'Integrity verified',sub:'Every record is signed, chained, and bound to a trusted external timestamp. Nothing was altered, reordered, deleted, or back-dated.',badge:'Integrity verified'};
}

function pill(on, label){ return `<span class="check ${on?'on':'off'}">${on?CHECK:DOT}${esc(label)}</span>`; }

function checksRow(rep, codes){
  const ok=rep.ok;
  const tlog = codes.has('tlog_inclusion_witnessed_ok')||codes.has('tlog_inclusion_unwitnessed');
  const tsPresent = !codes.has('no_anchor');
  const tsTrusted = ok && !codes.has('local_anchor_only') && !codes.has('no_anchor') && !codes.has('anchor_rfc3161_unchecked');
  const redacted = codes.has('redaction_summary');
  const pills=[ pill(ok,'Hash chain'), pill(ok,'Signatures'),
    pill(tsTrusted, tsPresent?'Trusted timestamp':'No timestamp') ];
  if(tlog) pills.push(pill(true,'Transparency log'));
  if(redacted) pills.push(pill(true,'Redaction'));
  return `<div class="checks">${pills.join('')}</div>`;
}

const SHIELD='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';

function redactionPanel(rep){
  const f=(rep.findings||[]).find(x=>x.code==='redaction_summary');
  const bad=(rep.findings||[]).find(x=>x.code==='redaction_disclosure_invalid');
  if(!f && !bad) return '';
  const detail = f ? f.detail : 'a supplied disclosure does not match its commitment';
  const m = /(\d+)\s+withheld or erased/.exec(detail);
  const withheld = m ? parseInt(m[1],10) : 0;
  let hint='';
  if(bad){ hint='<div class="rhint"><b>A supplied opening did not match its commitment.</b> The disclosed value is not what was recorded; this is reported as tampering above.</div>'; }
  else if(withheld>0 && !openings){ hint='<div class="rhint"><b>Privacy-protected fields are present.</b> Drop the operator&#39;s <code style="font-family:var(--font-mono)">openings.json</code> to disclose and verify them. Without it they stay redacted, and the record still verifies.</div>'; }
  else if(withheld>0){ hint='<div class="rhint">Some fields remain withheld or erased; that is the right-to-erasure path and the record still verifies.</div>'; }
  return `<div class="redact"><div class="rt">${SHIELD}Selective disclosure</div><div class="rd">${esc(detail)}.</div>${hint}</div>`;
}

function renderReport(rep, mode){
  const c=classify(rep);
  const codes=new Set((rep.findings||[]).map(f=>f.code));
  const sev={fail:0,warn:1,info:2};
  const fs=(rep.findings||[]).slice().sort((a,b)=>sev[a.severity]-sev[b.severity]);
  const rows=fs.map(f=>`<div class="f ${esc(f.severity)}"><span class="sev">${esc(f.severity)}</span><div class="fc"><div class="code">${esc(f.code)}</div><div class="detail">${esc(f.detail)}</div></div></div>`).join('');
  const where = mode==='browser' ? 'Verified in your browser, trusting no server.' : 'Verified on the server.';
  show(`
    <div class="verdict ${c.st}">
      <span class="vbadge"><span class="bd"></span>${esc(c.badge)}</span>
      <div class="vmeta"><div class="h">${esc(c.head)}</div><div class="s">${esc(c.sub)} <span style="color:var(--text-lo)">${esc(where)}</span></div></div>
    </div>
    ${checksRow(rep, codes)}
    ${redactionPanel(rep)}
    <div class="findings">
      <div class="fhead"><span>Findings</span><span class="ct">${rep.fail||0} fail &middot; ${rep.warn||0} warn &middot; ${fs.length} total</span></div>
      ${rows||'<div class="f info"><span class="sev">info</span><div class="fc"><div class="code">no findings</div></div></div>'}
    </div>
    <div class="again"><button class="btn ghost" onclick="location.reload()">Verify another</button></div>`);
}

async function verify(){
  if(!bundle){ return; }
  show('<div class="verdict error"><span class="spin"></span><div class="vmeta"><div class="h">Verifying...</div><div class="s">Recomputing hashes, signatures, chains, and timestamps.</div></div></div>');
  // Prefer fully client-side verification: trust not even this server. Fall back to the
  // server-side verifier only if the browser module is unavailable.
  const ops = openings ? (openings.openings||openings) : null;
  try{
    const mod=await import('/verify.js');
    const rep=await mod.verifyBundle(bundle,pin,{openings:ops});
    renderReport(rep,'browser');
    return;
  }catch(_){ /* fall through to server verify */ }
  try{
    const r=await fetch('/v1/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bundle,pin,openings:ops})});
    if(r.status===429){ throw new Error('Rate limited, wait a moment and retry.'); }
    if(!r.ok){ const e=await r.json().catch(()=>({detail:'verification failed'})); throw new Error(e.detail||('failed ('+r.status+')')); }
    renderReport(await r.json(),'server');
  }catch(e){
    show(`<div class="verdict error"><span class="vbadge"><span class="bd"></span>Could not verify</span><div class="vmeta"><div class="h">Could not verify</div><div class="s">${esc(e.message)}</div></div></div><div class="again"><button class="btn ghost" onclick="location.reload()">Try again</button></div>`);
  }
}

function ingest(text, name){
  let j; try{ j=JSON.parse(text); }catch(_){ show('<div class="verdict error"><span class="vbadge"><span class="bd"></span>Invalid JSON</span><div class="vmeta"><div class="h">That file is not valid JSON</div></div></div>'); return; }
  if(j && j.format==='flightrecorder.bundle/1'){ bundle=j; }
  else if(j && (j.format==='flightrecorder.openings/1' || j.openings)){ openings=j; }
  else if(j && (j.pin_sig||j.server_record_hash) && j.stream_id && j.recv_seq!==undefined){ pin=j; }
  else if(j && j.records){ bundle=j; }
  else { pin=j; }
  if(bundle) verify();
  else if(openings) show('<div class="verdict amber"><span class="vbadge"><span class="bd"></span>Openings loaded</span><div class="vmeta"><div class="h">Disclosure keystore loaded</div><div class="s">Now add the bundle.json; its privacy-protected fields will be disclosed and verified.</div></div></div>');
  else show('<div class="verdict amber"><span class="vbadge"><span class="bd"></span>Pin loaded</span><div class="vmeta"><div class="h">Pin loaded</div><div class="s">Now add the bundle.json to verify against this pin.</div></div></div>');
}

function readFiles(files){
  [...files].forEach(f=>{ const rd=new FileReader(); rd.onload=()=>ingest(rd.result,f.name); rd.readAsText(f); });
}
$('#pick').onclick=e=>{ e.stopPropagation(); $('#file').click(); };
$('#file').onchange=e=>readFiles(e.target.files);
drop.onclick=()=>$('#file').click();
drop.onkeydown=e=>{ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); $('#file').click(); } };
['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over');}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over');}));
drop.addEventListener('drop',e=>readFiles(e.dataTransfer.files));
$('#verifyPaste').onclick=()=>{ const t=$('#ta').value.trim(); if(t) ingest(t,'pasted'); };
</script>
</body>
</html>
"""
