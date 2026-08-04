"""The Run Explorer: an authenticated, single-file dashboard served by the sink.

This is the daily-use surface. It reads the account-scoped analytics API (/v1/overview,
/v1/streams/{id}/summary, /v1/streams/{id}/sessions/{sid}) and renders streams, sessions,
event timelines, token/cost rollups, and a live integrity verdict per stream. It is
deliberately a zero-build, dependency-free page (inlined CSS + vanilla JS) so it deploys
anywhere the server runs. Aesthetic matches the marketing site: aerospace-industrial dark,
DM Mono + DM Sans, signal-green accent.
"""

from __future__ import annotations

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex">
<title>Run Explorer | Provenrail</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,400&family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0b0e;--bg-2:#0f1115;--bg-3:#14171c;--bg-4:#1b1f26;
  --border:#20242c;--border-hi:#2e333d;
  --accent:#2ee6a6;--accent-dim:#16c489;--accent-glow:rgba(46,230,166,.16);--accent-glow-sm:rgba(46,230,166,.07);
  /* --accent is a SURFACE colour (button fills, borders, focus rings). --accent-text is the
     text-role twin: the same brand green fails 4.5:1 as light-mode text, and the figure it
     was used for is the cost, which is the number a buyer most needs to read. */
  --accent-text:#2ee6a6;
  --text-hi:#f3f5f7;--text-mid:#99a2af;--text-lo:#858f9c;--text-mono:#c9d0d9;
  --green:#2ee6a6;--green-glow:rgba(46,230,166,.14);--red:#f06a5d;--red-glow:rgba(240,106,93,.14);
  --amber:#f0b23a;--amber-glow:rgba(240,178,58,.14);--blue:#2ee6a6;
  --font-mono:'DM Mono','Fira Code',ui-monospace,monospace;--font-body:'DM Sans',system-ui,-apple-system,sans-serif;
  --r-sm:4px;--r-md:8px;--r-lg:12px;--r-xl:18px;
  --gutter:clamp(1rem,4vw,2.5rem);--max-w:1180px;
  --ease-out:cubic-bezier(.16,1,.3,1);
}
@media (prefers-color-scheme:light){:root{
  --bg:#fbfcfd;--bg-2:#f5f7f9;--bg-3:#ffffff;--bg-4:#eef1f4;--border:#e4e8ee;--border-hi:#d2d8e0;
  --accent:#07a06a;--accent-dim:#058a5b;--accent-glow:rgba(7,160,106,.14);--accent-glow-sm:rgba(7,160,106,.06);
  --accent-text:#087a4e;
  --green:#07a06a;--green-glow:rgba(7,160,106,.14);
  --text-hi:#0c0f14;--text-mid:#515b67;--text-lo:#656d78;--text-mono:#1b2430;}}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px;-webkit-font-smoothing:antialiased;scroll-behavior:smooth}
body{font-family:var(--font-body);line-height:1.55;color:var(--text-hi);background:var(--bg);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.55;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='0.035'/%3E%3C/svg%3E")}
a{color:inherit;text-decoration:none}
button{cursor:pointer;font-family:inherit;color:inherit;background:none;border:none}
.mono{font-family:var(--font-mono)}
[hidden]{display:none!important}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:var(--r-sm)}
::selection{background:var(--accent-glow);color:var(--text-hi)}
::-webkit-scrollbar{width:7px;height:7px}::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border-hi);border-radius:4px}

/* ---- topbar ---- */
.topbar{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:1rem;
  padding:.7rem var(--gutter);background:color-mix(in srgb,var(--bg) 84%,transparent);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;min-height:44px;gap:.6rem;font-family:var(--font-mono);font-size:.86rem;letter-spacing:.04em;font-weight:500}
.brand svg{width:26px;height:26px;flex-shrink:0}
.brand .sub{color:var(--text-lo);font-size:.7rem;letter-spacing:.14em;text-transform:uppercase}
.topbar-spacer{flex:1}
.conn{display:flex;align-items:center;gap:.45rem;font-family:var(--font-mono);font-size:.72rem;color:var(--text-mid);
  padding:.35rem .6rem;border:1px solid var(--border);border-radius:999px;background:var(--bg-2)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 0 0 var(--green-glow)}
.dot.live{animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.45;transform:scale(.7)}}
.tbtn{display:inline-flex;align-items:center;gap:.4rem;font-size:.78rem;color:var(--text-mid);
  padding:.45rem .7rem;border:1px solid var(--border);border-radius:var(--r-sm);min-height:38px;
  transition:color .15s,border-color .15s,background .15s}
.tbtn:hover{color:var(--text-hi);border-color:var(--border-hi);background:var(--bg-3)}
.tbtn.on{color:var(--accent);border-color:var(--accent);background:var(--accent-glow-sm)}
@media(max-width:640px){
  .tbtn .lbl{display:none}
  .brand .sub{display:none}
  /* The topbar's fixed 1rem gaps plus the gutter pushed the last button past the
     viewport on a 375px screen, so every route scrolled sideways. Tighten the gaps and
     let the row wrap instead of overflowing. */
  .topbar{gap:.5rem;flex-wrap:wrap}
  .conn{padding:.3rem .5rem}
}

/* ---- layout ---- */
.wrap{position:relative;z-index:1;max-width:var(--max-w);margin:0 auto;padding:clamp(1.25rem,4vw,2.5rem) var(--gutter) 5rem}
.crumb{display:flex;align-items:center;gap:.5rem;font-family:var(--font-mono);font-size:.74rem;color:var(--text-lo);margin-bottom:1.25rem;flex-wrap:wrap}
.crumb a{color:var(--text-mid);transition:color .15s}.crumb a:hover{color:var(--accent)}
.crumb .sep{color:var(--text-lo)}
.page-head{margin-bottom:1.75rem}
.eyebrow{font-family:var(--font-mono);font-size:.7rem;letter-spacing:.14em;text-transform:uppercase;color:var(--accent-text);
  display:flex;align-items:center;gap:.5rem;margin-bottom:.6rem}
.eyebrow::before{content:'';width:16px;height:1px;background:var(--accent)}
.h1{font-family:var(--font-mono);font-size:clamp(1.5rem,3.5vw,2.1rem);font-weight:500;letter-spacing:-.02em;line-height:1.15}
.lede{color:var(--text-mid);font-size:.95rem;margin-top:.4rem;max-width:60ch}

/* ---- stat tiles ---- */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--border);
  border:1px solid var(--border);border-radius:var(--r-lg);overflow:hidden;margin-bottom:1.75rem}
.tile{background:var(--bg-2);padding:1.1rem 1.15rem;position:relative;transition:background .2s}
.tile:hover{background:var(--bg-3)}
.tile .k{font-family:var(--font-mono);font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;color:var(--text-lo);margin-bottom:.55rem}
.tile .v{font-family:var(--font-mono);font-size:1.55rem;font-weight:500;color:var(--text-hi);line-height:1;letter-spacing:-.01em}
.tile .v small{font-size:.8rem;color:var(--text-lo);font-weight:400}
.tile .x{font-size:.72rem;color:var(--text-mid);margin-top:.4rem}
.tile.accent .v{color:var(--accent-text)}

/* ---- stream cards ---- */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1rem}
.card{display:block;background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-lg);
  padding:1.2rem 1.25rem;position:relative;overflow:hidden;transition:border-color .18s,transform .18s,background .18s}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--accent),transparent);opacity:0;transition:opacity .2s}
.card:hover{border-color:var(--border-hi);transform:translateY(-2px);background:var(--bg-3)}
.card:hover::before{opacity:1}
.card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:.75rem;margin-bottom:1rem}
.card-label{font-family:var(--font-mono);font-size:.92rem;font-weight:500;color:var(--text-hi);word-break:break-word;line-height:1.3}
.card-id{font-family:var(--font-mono);font-size:.68rem;color:var(--text-lo);margin-top:.25rem}
.card-meta{display:grid;grid-template-columns:1fr 1fr;gap:.55rem .75rem;margin-top:.25rem}
.cm{display:flex;flex-direction:column;gap:.15rem}
.cm .k{font-family:var(--font-mono);font-size:.62rem;letter-spacing:.08em;text-transform:uppercase;color:var(--text-lo)}
.cm .v{font-family:var(--font-mono);font-size:.92rem;color:var(--text-mono)}
.card-foot{display:flex;align-items:center;justify-content:space-between;gap:.5rem;margin-top:1rem;
  padding-top:.85rem;border-top:1px solid var(--border)}
.card-foot .when{font-size:.72rem;color:var(--text-lo);font-family:var(--font-mono)}

/* A denied action is the thing a reviewer scans for, so it gets the only red row in the
   timeline and the only red tile on the page. */
.tile.danger{border-color:color-mix(in srgb,var(--red) 45%,transparent);background:var(--red-glow)}
.tile.danger .v{color:var(--red)}
.tl-item[data-kind="policy"] .tl-dot{background:var(--red)}
.tl-item[data-kind="policy"] .tl-card{border-color:color-mix(in srgb,var(--red) 35%,transparent)}
.tl-item[data-kind="policy"] .tl-sum{color:var(--red)}

/* ---- integrity badge ---- */
.badge{display:inline-flex;align-items:center;gap:.4rem;font-family:var(--font-mono);font-size:.7rem;font-weight:500;
  letter-spacing:.02em;padding:.32rem .6rem;border-radius:999px;border:1px solid;white-space:nowrap}
.badge .bd{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.badge.verified{color:var(--green);border-color:color-mix(in srgb,var(--green) 45%,transparent);background:var(--green-glow)}
.badge.verified .bd{background:var(--green)}
.badge.amber{color:var(--amber);border-color:color-mix(in srgb,var(--amber) 45%,transparent);background:var(--amber-glow)}
.badge.amber .bd{background:var(--amber)}
.badge.tampered{color:var(--red);border-color:color-mix(in srgb,var(--red) 45%,transparent);background:var(--red-glow)}
.badge.tampered .bd{background:var(--red)}
.badge.empty,.badge.neutral{color:var(--text-lo);border-color:var(--border);background:var(--bg-3)}
.badge.empty .bd,.badge.neutral .bd{background:var(--text-lo)}
.badge.live{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 45%,transparent);background:var(--accent-glow-sm)}
.badge.live .bd{background:var(--accent);animation:pulse 2s ease-in-out infinite}

/* ---- integrity banner ---- */
.banner{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;border:1px solid var(--border);border-left-width:3px;
  border-radius:var(--r-md);padding:1rem 1.2rem;margin-bottom:1.5rem;background:var(--bg-2)}
.banner.verified{border-left-color:var(--green)}.banner.amber{border-left-color:var(--amber)}
.banner.tampered{border-left-color:var(--red)}.banner.empty{border-left-color:var(--text-lo)}
.banner .bh{font-family:var(--font-mono);font-size:1rem;font-weight:500;color:var(--text-hi)}
.banner .bx{font-size:.82rem;color:var(--text-mid);margin-top:.2rem}
.banner-spacer{flex:1;min-width:1rem}

/* ---- table ---- */
.panel{border:1px solid var(--border);border-radius:var(--r-lg);overflow:hidden;background:var(--bg-2)}
.panel-head{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.85rem 1.15rem;border-bottom:1px solid var(--border);background:var(--bg-3)}
.panel-head .t{font-family:var(--font-mono);font-size:.78rem;letter-spacing:.06em;text-transform:uppercase;color:var(--text-mid)}
.rows{display:flex;flex-direction:column}
.row{display:grid;grid-template-columns:1.4fr .9fr .7fr .7fr .9fr auto;gap:.75rem;align-items:center;
  padding:.85rem 1.15rem;border-bottom:1px solid var(--border);transition:background .15s;cursor:pointer;text-align:left;width:100%}
.row:last-child{border-bottom:0}
.row:hover{background:var(--bg-3)}
.row .c-main{display:flex;flex-direction:column;gap:.2rem;min-width:0}
.row .c-main .pri{font-family:var(--font-mono);font-size:.84rem;color:var(--text-hi);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row .c-main .sec{font-size:.72rem;color:var(--text-lo)}
.cell{font-family:var(--font-mono);font-size:.82rem;color:var(--text-mono)}
.cell .ck{display:none}
.cell.muted{color:var(--text-lo)}
@media(max-width:760px){
  .row{grid-template-columns:1fr auto;gap:.5rem .75rem}
  .row .cell{font-size:.78rem}
  .cell .ck{display:inline;font-size:.6rem;letter-spacing:.08em;text-transform:uppercase;color:var(--text-lo);margin-right:.4rem}
  .row .hide-sm{display:none}
}

/* ---- timeline ---- */
.timeline{display:flex;flex-direction:column;position:relative}
.tl-item{position:relative;padding:0 0 .25rem 2.1rem;border-left:1px solid var(--border);margin-left:.6rem}
.tl-item:last-child{border-left-color:transparent}
.tl-dot{position:absolute;left:-5px;top:.95rem;width:9px;height:9px;border-radius:50%;background:var(--bg);border:2px solid var(--accent)}
.tl-item[data-kind="lifecycle"] .tl-dot{border-color:var(--text-lo)}
.tl-item[data-kind="model"] .tl-dot{border-color:var(--accent)}
.tl-item[data-kind="tool"] .tl-dot{border-color:var(--blue)}
.tl-item[data-kind="decision"] .tl-dot{border-color:var(--green)}
.tl-item[data-kind="data"] .tl-dot{border-color:var(--amber)}
.tl-item[data-kind="human"] .tl-dot{border-color:#c084fc}
.tl-card{background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-md);margin:.45rem 0;
  transition:border-color .15s,background .15s}
.tl-card:hover{border-color:var(--border-hi)}
.tl-head{display:flex;align-items:center;gap:.7rem;padding:.7rem .9rem;width:100%;text-align:left}
.tl-seq{font-family:var(--font-mono);font-size:.66rem;color:var(--text-lo);min-width:2.2rem}
.tl-type{font-family:var(--font-mono);font-size:.82rem;color:var(--text-hi);font-weight:500;white-space:nowrap}
.tl-sum{font-size:.8rem;color:var(--text-mid);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tl-cost{font-family:var(--font-mono);font-size:.74rem;color:var(--accent);white-space:nowrap}
.tl-time{font-family:var(--font-mono);font-size:.68rem;color:var(--text-lo);white-space:nowrap}
.tl-chev{color:var(--text-lo);transition:transform .2s;flex-shrink:0}
.tl-card.open .tl-chev{transform:rotate(90deg)}
.tl-body{display:none;padding:0 .9rem .85rem 4.9rem;font-family:var(--font-mono);font-size:.74rem;color:var(--text-mid);line-height:1.7}
.tl-card.open .tl-body{display:block}
.tl-kv{display:flex;gap:.6rem}.tl-kv .k{color:var(--text-lo);min-width:5.5rem}.tl-kv .v{color:var(--text-mono);word-break:break-all}
@media(max-width:640px){/* The summary is the only human-readable part of a timeline row. Hiding it at mobile
   left four consecutive rows all reading 'Tool call 17:54:33' with nothing to tell
   them apart, so the time goes instead and the summary truncates. */
.tl-time{display:none}.tl-body{padding-left:1rem}}
/* Replay scrubber: step through a run one action at a time. The reason this exists rather
   than a scrolling list alone is that "what did the agent do at step 14, and how does that
   differ from the run that worked" is the question a debugger actually has. */
.scrub{background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-md);padding:.85rem .9rem;margin-bottom:.9rem}
.scrub-top{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;margin-bottom:.65rem}
.scrub-btn{font-family:var(--font-mono);font-size:.78rem;min-width:44px;min-height:44px;display:inline-flex;align-items:center;justify-content:center;padding:.35rem .6rem;border:1px solid var(--border-hi);
  border-radius:var(--r-sm);color:var(--text-hi);background:var(--bg-3);cursor:pointer}
.scrub-btn:hover{border-color:var(--accent);color:var(--accent)}
.scrub-btn[disabled]{opacity:.4;cursor:not-allowed;border-color:var(--border)}
.scrub-pos{font-family:var(--font-mono);font-size:.76rem;color:var(--text-lo);min-width:6.5rem}
.scrub-sel{font-family:var(--font-mono);font-size:.74rem;background:var(--bg-3);color:var(--text-hi);
  border:1px solid var(--border-hi);border-radius:var(--r-sm);padding:.3rem .4rem;max-width:14rem}
.scrub input[type=range]{width:100%;accent-color:var(--accent)}
.scrub-track{display:flex;gap:2px;margin-top:.45rem}
.scrub-tick{flex:1;height:4px;border-radius:2px;background:var(--border-hi)}
.scrub-tick.on{background:var(--accent)}
/* Shape as well as colour: protanopia shifts this red toward the unfilled grey, so a
   red-only marker is invisible to roughly 1 in 25 men. Square means "differs". */
.scrub-tick.diff{background:var(--red);border-radius:0;height:7px;margin-top:-1.5px}
.scrub-frame{margin-top:.7rem;border-top:1px solid var(--border);padding-top:.7rem;
  font-family:var(--font-mono);font-size:.76rem;color:var(--text-mid);line-height:1.7}
.scrub-frame .h{color:var(--text-hi);font-size:.85rem;margin-bottom:.3rem}
.scrub-frame .d{color:var(--red)}
.tl-item.cursor .tl-card{border-color:var(--accent)}
.tl-item.diff .tl-dot{border-color:var(--red)}
@media(max-width:640px){.scrub-pos{min-width:0}}

/* ---- chips ---- */
.chips{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.9rem}
.chip{font-family:var(--font-mono);font-size:.7rem;color:var(--text-mid);background:var(--accent-glow-sm);
  border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);padding:.22rem .55rem;border-radius:999px;
  /* Session meta can hold a full 64-char hash (the policy commitment), which is wider than
     a phone. Break it rather than letting one chip scroll the whole page sideways. */
  max-width:100%;overflow-wrap:anywhere;word-break:break-word}

/* ---- connect gate ---- */
.gate{max-width:440px;margin:8vh auto 0;position:relative;z-index:1}
.gate-card{background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-xl);padding:2rem 1.85rem;
  box-shadow:0 24px 60px -30px rgba(0,0,0,.6)}
.gate h2{font-family:var(--font-mono);font-size:1.25rem;font-weight:500;margin-bottom:.5rem;letter-spacing:-.01em}
.gate p{font-size:.88rem;color:var(--text-mid);margin-bottom:1.5rem;line-height:1.6}
.field{margin-bottom:1rem}
.field label{display:block;font-family:var(--font-mono);font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;color:var(--text-lo);margin-bottom:.45rem}
.field input{width:100%;font-family:var(--font-mono);font-size:.85rem;color:var(--text-hi);background:var(--bg);
  border:1px solid var(--border-hi);border-radius:var(--r-md);padding:.7rem .85rem;min-height:46px;transition:border-color .15s}
.field input:focus{outline:none;border-color:var(--accent)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;width:100%;font-size:.9rem;font-weight:600;
  background:var(--accent);color:#fff;border-radius:var(--r-md);padding:.8rem 1rem;min-height:48px;
  transition:background .15s,transform .12s}
.btn:hover{background:var(--accent-dim);transform:translateY(-1px)}.btn:active{transform:translateY(0)}
.btn.ghost{background:transparent;color:var(--text-hi);border:1px solid var(--border-hi);font-weight:500}
.btn.ghost:hover{border-color:var(--accent);background:var(--accent-glow-sm)}
.gate-or{display:flex;align-items:center;gap:.75rem;margin:1.25rem 0;color:var(--text-lo);font-family:var(--font-mono);font-size:.72rem}
.gate-or::before,.gate-or::after{content:'';flex:1;height:1px;background:var(--border)}
.gate-err{color:var(--red);font-size:.8rem;margin-top:.85rem;min-height:1.1rem;font-family:var(--font-mono)}
.keybox{background:var(--bg);border:1px solid var(--accent);border-radius:var(--r-md);padding:.85rem;margin-top:1rem}
.keybox .kl{font-family:var(--font-mono);font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;color:var(--accent);margin-bottom:.4rem}
.keybox code{font-family:var(--font-mono);font-size:.78rem;color:var(--text-hi);word-break:break-all;display:block}
.keybox .warn{font-size:.74rem;color:var(--text-lo);margin-top:.5rem}

/* ---- misc ---- */
.empty-state{text-align:center;padding:4rem 1rem;color:var(--text-lo)}
.empty-state .ic{font-family:var(--font-mono);font-size:2rem;color:var(--border-hi);margin-bottom:1rem}
.empty-state .t{font-family:var(--font-mono);color:var(--text-mid);margin-bottom:.5rem}
.empty-state .d{font-size:.85rem;max-width:42ch;margin:0 auto;line-height:1.6}
.skeleton{background:linear-gradient(90deg,var(--bg-2),var(--bg-3),var(--bg-2));background-size:200% 100%;
  animation:shimmer 1.3s infinite;border-radius:var(--r-md)}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.actions{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:1.5rem}
.verify-cmd{font-family:var(--font-mono);font-size:.76rem;color:var(--text-mono);background:var(--bg);border:1px solid var(--border);
  border-radius:var(--r-md);padding:.65rem .85rem;overflow-x:auto;white-space:nowrap;margin-top:.5rem}
.verify-cmd .p{color:var(--text-lo);user-select:none}
.fade{animation:fade .4s var(--ease-out) both}
@keyframes fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.toast{position:fixed;bottom:1.25rem;left:50%;transform:translateX(-50%) translateY(2rem);z-index:99;
  background:var(--bg-3);border:1px solid var(--border-hi);border-radius:var(--r-md);padding:.7rem 1.1rem;
  font-family:var(--font-mono);font-size:.78rem;color:var(--text-hi);opacity:0;transition:opacity .25s,transform .25s;pointer-events:none}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important}}
</style>
</head>
<body>
<header class="topbar">
  <a class="brand" href="#/" aria-label="Provenrail home">
    <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" width="26" height="26">
      <rect x="2.5" y="2.5" width="27" height="27" rx="9" fill="var(--bg-3)" stroke="var(--accent)" stroke-opacity=".4" stroke-width="1.5"/>
      <path d="M9 17l4.4 4.4L23 11" stroke="var(--accent)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="9" cy="17" r="1.8" fill="var(--accent)"/>
      <circle cx="23" cy="11" r="1.8" fill="var(--accent)"/>
    </svg>
    <span>proven<span style="color:var(--accent-text)">rail</span> <span class="sub">Run Explorer</span></span>
  </a>
  <div class="topbar-spacer"></div>
  <div class="conn" id="conn" hidden><span class="dot" id="conn-dot"></span><span id="conn-txt">connecting</span></div>
  <a class="tbtn" id="alerts-link" href="#/alerts" title="Integrity alerts" hidden>
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
    <span class="lbl">Alerts</span></a>
  <button class="tbtn" id="live-btn" title="Auto-refresh every 5s" hidden><span class="dot" style="background:var(--text-lo)" id="live-dot"></span><span class="lbl">Live</span></button>
  <button class="tbtn" id="refresh-btn" title="Refresh" hidden>
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
    <span class="lbl">Refresh</span></button>
  <button class="tbtn" id="logout-btn" title="Disconnect" hidden>Disconnect</button>
</header>
<main id="root" class="wrap"></main>
<div class="toast" id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const KEY = 'pr_account_key';
const state = { key: localStorage.getItem(KEY) || '', openMode: false, live: false, timer: null, route: null };

/* ---------- helpers ---------- */
const esc = s => String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function fmtNum(n){ n=Number(n)||0; return n.toLocaleString('en-US'); }
function fmtTokens(n){ n=Number(n)||0; if(n<1000) return String(n); if(n<1e6) return (n/1e3).toFixed(n<1e4?1:0)+'k'; return (n/1e6).toFixed(2)+'M'; }
function fmtCost(n){ n=Number(n)||0; if(n===0) return '$0.00'; if(n<0.0001) return '<$0.0001'; if(n<1) return '$'+n.toFixed(4); if(n<100) return '$'+n.toFixed(3); return '$'+n.toFixed(2); }
function shortId(s){ return s? String(s).slice(0,8) : '-'; }
function dur(s){ if(s==null) return '-'; s=Math.max(0,Math.round(s)); if(s<60) return s+'s'; const m=Math.floor(s/60), r=s%60; if(m<60) return m+'m '+r+'s'; const h=Math.floor(m/60); return h+'h '+(m%60)+'m'; }
function ago(ts){ if(!ts) return '-'; const t=Date.parse(ts.replace('Z','+00:00')); if(isNaN(t)) return '-'; let d=(Date.now()-t)/1000; if(d<60) return Math.floor(d)+'s ago'; if(d<3600) return Math.floor(d/60)+'m ago'; if(d<86400) return Math.floor(d/3600)+'h ago'; return Math.floor(d/86400)+'d ago'; }
function clock(ts){ if(!ts) return '-'; return esc((ts.slice(11,19))||''); }
function kindOf(at){ if(at&&at.indexOf('lifecycle')===0) return 'lifecycle'; if(at==='model_call') return 'model'; if(at==='tool_call'||at==='mcp_call') return 'tool'; if(at==='policy.decision') return 'policy'; if(at==='decision') return 'decision'; if(at==='data_access') return 'data'; if(at==='human_oversight') return 'human'; return 'lifecycle'; }
function badge(v){ const m={verified:'Verified',amber:'No timestamp',tampered:'Tampering',empty:'No records',neutral:'-'}; const st=(v&&v.state)||'neutral'; return `<span class="badge ${st}"><span class="bd"></span>${m[st]||st}</span>`; }
function toast(msg){ const t=$('#toast'); t.textContent=msg; t.classList.add('show'); clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('show'),2200); }

async function api(path){
  const h={}; if(state.key) h['Authorization']='Bearer '+state.key;
  const r=await fetch(path,{headers:h});
  if(r.status===401){ const e=new Error('unauthorized'); e.code=401; throw e; }
  if(!r.ok){ const e=new Error('request failed ('+r.status+')'); e.code=r.status; throw e; }
  return r.json();
}

/* ---------- chrome ---------- */
function setConn(ok){
  $('#conn').hidden=false; $('#conn-txt').textContent = state.openMode? 'open mode' : (ok?'connected':'offline');
  $('#conn-dot').style.background = ok? 'var(--green)':'var(--red)';
  for(const id of ['#live-btn','#refresh-btn','#alerts-link']) $(id).hidden=false;
  $('#logout-btn').hidden = state.openMode;
}
function hideChrome(){ $('#conn').hidden=true; for(const id of ['#live-btn','#refresh-btn','#logout-btn']) $(id).hidden=true; }
$('#refresh-btn').onclick=()=>render(true);
$('#logout-btn').onclick=()=>{ localStorage.removeItem(KEY); state.key=''; location.hash='#/'; render(true); };
$('#live-btn').onclick=()=>{
  state.live=!state.live; $('#live-btn').classList.toggle('on',state.live);
  $('#live-dot').style.background = state.live? 'var(--accent)':'var(--text-lo)';
  $('#live-dot').classList.toggle('live',state.live);
  if(state.live){ state.timer=setInterval(()=>render(true),5000); } else { clearInterval(state.timer); }
};

/* ---------- connect gate ---------- */
function renderGate(err){
  hideChrome();
  $('#root').innerHTML = `
  <div class="gate fade">
    <div class="gate-card">
      <h2>Connect your sink</h2>
      <p>The Run Explorer reads your account's streams. Paste an account API key, or create one now. The key stays in this browser only.</p>
      <div class="field">
        <label for="k">Account API key</label>
        <input id="k" type="password" placeholder="pr_sk_..." autocomplete="off" spellcheck="false">
      </div>
      <button class="btn" id="connect">Connect</button>
      <div class="gate-or">or</div>
      <button class="btn ghost" id="create">Create a new account</button>
      <div class="gate-err" id="gerr">${err?esc(err):''}</div>
      <div id="newkey"></div>
    </div>
  </div>`;
  $('#k').onkeydown=e=>{ if(e.key==='Enter') $('#connect').click(); };
  $('#connect').onclick=async()=>{
    const v=$('#k').value.trim(); if(!v){ $('#gerr').textContent='Enter a key.'; return; }
    state.key=v; try{ await api('/v1/overview'); localStorage.setItem(KEY,v); render(true); }
    catch(e){ state.key=''; $('#gerr').textContent = e.code===401?'That key was rejected.':'Could not reach the sink.'; }
  };
  $('#create').onclick=async()=>{
    $('#gerr').textContent='';
    try{
      const r=await fetch('/v1/accounts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:'dashboard'})});
      if(!r.ok) throw new Error('failed'); const d=await r.json();
      state.key=d.api_key; localStorage.setItem(KEY,d.api_key);
      $('#newkey').innerHTML=`<div class="keybox"><div class="kl">Save this key now, shown once</div><code>${esc(d.api_key)}</code><div class="warn">Stored in this browser. Loading your dashboard...</div></div>`;
      setTimeout(()=>render(true),1600);
    }catch(e){ $('#gerr').textContent='Could not create an account (sign-up may be rate limited).'; }
  };
}

/* ---------- views ---------- */
function tiles(t){
  const showStreams = typeof t.streams === 'number';
  return `<div class="tiles">
    ${showStreams?`<div class="tile"><div class="k">Streams</div><div class="v">${fmtNum(t.streams)}</div></div>`:''}
    <div class="tile"><div class="k">Sessions</div><div class="v">${fmtNum(t.sessions)}</div>${t.open_sessions?`<div class="x">${t.open_sessions} live</div>`:''}</div>
    <div class="tile"><div class="k">Events</div><div class="v">${fmtNum(t.events)}</div></div>
    <div class="tile"><div class="k">Model calls</div><div class="v">${fmtNum(t.model_calls)}</div><div class="x">${fmtNum(t.tool_calls)} tool calls</div></div>
    <div class="tile"><div class="k">Tokens</div><div class="v">${fmtTokens((t.tokens_in||0)+(t.tokens_out||0))}</div><div class="x">${fmtTokens(t.tokens_in)} in / ${fmtTokens(t.tokens_out)} out</div></div>
    <div class="tile accent"><div class="k">Est. cost</div><div class="v">${fmtCost(t.cost_usd)}</div>${t.unpriced_calls?`<div class="x">${t.unpriced_calls} unpriced</div>`:''}</div>
    ${typeof t.policy_denials==='number'?`<div class="tile${t.policy_denials?' danger':''}"><div class="k">Blocked</div><div class="v">${fmtNum(t.policy_denials)}</div><div class="x">${t.policy_denials?'policy denied':(t.policy_allows?'none blocked':'no policy')}</div></div>`:''}
  </div>`;
}

async function renderOverview(){
  const d=await api('/v1/overview'); state.openMode=d.open_mode; setConn(true);
  const t={...d.totals, streams:d.streams.length};
  let cards;
  if(!d.streams.length){
    cards=`<div class="empty-state"><div class="ic">[ ]</div><div class="t">No streams yet</div><div class="d">Provision a stream and point an agent at this sink. Run <span class="mono">pr demo</span> for a self-contained example, then refresh.</div></div>`;
  } else {
    cards='<div class="cards">'+d.streams.map(s=>{
      const tt=s.totals||{}; const live=tt.open_sessions>0;
      return `<a class="card fade" href="#/s/${encodeURIComponent(s.stream_id)}">
        <div class="card-top">
          <div><div class="card-label">${esc(s.label||'Unlabeled stream')}</div><div class="card-id">${esc(shortId(s.stream_id))}</div></div>
          ${live?'<span class="badge live"><span class="bd"></span>Live</span>':badge(s.verdict)}
        </div>
        <div class="card-meta">
          <div class="cm"><span class="k">Sessions</span><span class="v">${fmtNum(tt.sessions||0)}</span></div>
          <div class="cm"><span class="k">Events</span><span class="v">${fmtNum(s.records||0)}</span></div>
          <div class="cm"><span class="k">Tokens</span><span class="v">${fmtTokens((tt.tokens_in||0)+(tt.tokens_out||0))}</span></div>
          <div class="cm"><span class="k">Est. cost</span><span class="v" style="color:var(--accent-text)">${fmtCost(tt.cost_usd)}</span></div>
        </div>
        <div class="card-foot"><span class="when">${s.last_activity?ago(s.last_activity):'no activity'}</span>${live?'':badge(s.verdict)}</div>
      </a>`;
    }).join('')+'</div>';
  }
  $('#root').innerHTML=`
    <div class="page-head fade">
      <div class="eyebrow">Overview</div>
      <h1 class="h1">What your agents recorded</h1>
      <p class="lede">A signed, hash-chained record of every run, across every stream. Each badge below is the standalone verifier's own verdict, not a status this page asserts.</p>
    </div>
    ${tiles(t)}
    ${cards}`;
}

async function renderStream(id){
  const d=await api('/v1/streams/'+encodeURIComponent(id)+'/summary'); state.openMode=state.openMode; setConn(true);
  const v=d.verdict||{state:'empty'}; const st=d.stream||{};
  const sessions=d.sessions||[];
  const bx={verified:'Every record is signed, chained, and bound to a trusted external timestamp. Verify it yourself below.',
    amber:'Records are signed and chained with no detected tampering, but no third-party trusted timestamp covers them yet, so nothing here proves WHEN they were written. Anchor with RFC 3161 to add that.',
    tampered:'The standalone verifier found '+ (v.fails||0) +' integrity failure(s). This record set has been altered, reordered, or truncated.',
    empty:'No records on this stream yet.'}[v.state]||'';
  const rows = sessions.length? sessions.map(s=>{
    const live=!s.sealed;
    return `<button class="row" onclick="location.hash='#/s/${encodeURIComponent(id)}/${encodeURIComponent(s.session_id)}'">
      <div class="c-main">
        <span class="pri">${esc(shortId(s.session_id))}${s.models&&s.models.length?' &middot; '+esc(s.models[0]):''}</span>
        <span class="sec">${esc(s.started_at?s.started_at.slice(0,19).replace('T',' '):'')} UTC</span>
      </div>
      <div class="cell hide-sm"><span class="ck">events</span>${fmtNum(s.events)}</div>
      <div class="cell hide-sm"><span class="ck">calls</span>${fmtNum(s.model_calls)}</div>
      <div class="cell hide-sm"><span class="ck">tokens</span>${fmtTokens((s.tokens_in||0)+(s.tokens_out||0))}</div>
      <div class="cell"><span class="ck">est. cost</span><span style="color:var(--accent-text)">${fmtCost(s.cost_usd)}</span></div>
      <div>${live?'<span class="badge live"><span class="bd"></span>Live</span>':`<span class="badge ${s.outcome==='failure'?'tampered':'verified'}"><span class="bd"></span>${esc(s.outcome||'sealed')}</span>`}</div>
    </button>`;
  }).join('') : `<div class="empty-state"><div class="ic">[ ]</div><div class="t">No sessions recorded</div></div>`;

  $('#root').innerHTML=`
    <div class="crumb fade"><a href="#/">Overview</a><span class="sep">/</span><span>${esc(st.label||shortId(id))}</span></div>
    <div class="page-head fade">
      <div class="eyebrow">Stream</div>
      <h1 class="h1">${esc(st.label||'Unlabeled stream')}</h1>
      <p class="lede mono" style="font-size:.8rem;color:var(--text-lo)">${esc(id)}</p>
    </div>
    <div class="banner ${v.state} fade">
      <div><div class="bh">${esc(v.headline||badgeText(v.state))}</div><div class="bx">${esc(bx)}</div></div>
      <div class="banner-spacer"></div>${badge(v)}
    </div>
    <div class="actions fade">
      <a class="tbtn" href="/v1/streams/${encodeURIComponent(id)}/bundle" id="dl">Download bundle</a>
      <button class="tbtn" id="dlndjson">Export NDJSON (SIEM)</button>
      <button class="tbtn" id="copyverify">Copy verify command</button>
      <span style="flex:1"></span>
      <select id="regime" class="tbtn" style="min-height:38px" aria-label="Attestation regime">
        <option value="eu-ai-act">EU AI Act</option><option value="hipaa">HIPAA</option><option value="generic">Generic</option>
      </select>
      <button class="tbtn on" id="dlpack" style="color:var(--accent);border-color:var(--accent)">Download evidence pack</button>
    </div>
    <div class="verify-cmd fade"><span class="p">$ </span>pr verify bundle.json${v.state==='verified'?'':' --pin pin.json'}</div>
    ${tiles({...d.totals, streams:1})}
    <div class="panel fade">
      <div class="panel-head"><span class="t">Sessions</span><span class="t" style="color:var(--text-lo)">${sessions.length} total</span></div>
      <div class="rows">${rows}</div>
    </div>`;
  // bundle download needs the auth header; intercept the link
  $('#dl').onclick=async(e)=>{ e.preventDefault(); try{ const b=await api('/v1/streams/'+encodeURIComponent(id)+'/bundle');
    const blob=new Blob([JSON.stringify(b,null,2)],{type:'application/json'}); const u=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=u; a.download='bundle-'+shortId(id)+'.json'; a.click(); URL.revokeObjectURL(u); toast('Bundle downloaded'); }catch(_){ toast('Download failed'); } };
  $('#copyverify').onclick=()=>{ navigator.clipboard.writeText('pr verify bundle.json'+(v.state==='verified'?'':' --pin pin.json')).then(()=>toast('Copied')); };
  $('#dlndjson').onclick=async()=>{
    try{ const h={}; if(state.key) h['Authorization']='Bearer '+state.key;
      const r=await fetch('/v1/streams/'+encodeURIComponent(id)+'/export.ndjson',{headers:h});
      if(!r.ok) throw new Error(); const blob=await r.blob(); const u=URL.createObjectURL(blob);
      const a=document.createElement('a'); a.href=u; a.download=shortId(id)+'.ndjson'; a.click(); URL.revokeObjectURL(u); toast('NDJSON exported');
    }catch(_){ toast('Export failed'); }
  };
  $('#dlpack').onclick=async()=>{
    const regime=$('#regime').value; toast('Building evidence pack...');
    try{ const h={}; if(state.key) h['Authorization']='Bearer '+state.key;
      const r=await fetch('/v1/streams/'+encodeURIComponent(id)+'/evidence?regime='+regime,{headers:h});
      if(!r.ok) throw new Error(); const blob=await r.blob(); const u=URL.createObjectURL(blob);
      const a=document.createElement('a'); a.href=u; a.download='evidence-'+shortId(id)+'-'+regime+'.zip'; a.click(); URL.revokeObjectURL(u);
      toast('Evidence pack downloaded');
    }catch(_){ toast('Could not build pack'); }
  };
}
function badgeText(st){ return {verified:'Integrity verified',amber:'Integrity verified, no trusted timestamp',tampered:'Tampering detected',empty:'No records'}[st]||''; }

async function renderSession(id,sid){
  const d=await api('/v1/streams/'+encodeURIComponent(id)+'/sessions/'+encodeURIComponent(sid)); setConn(true);
  const s=d.summary||{}; const ev=d.events||[]; const live=!s.sealed;
  const chips=(s.models||[]).map(m=>`<span class="chip">${esc(m)}</span>`).join('');
  const metaChips=Object.entries(s.meta||{}).map(([k,vv])=>`<span class="chip">${esc(k)}: ${esc(vv)}</span>`).join('');
  const items=ev.map(e=>{
    const kind=kindOf(e.action_type);
    const cost = e.cost && e.cost.priced ? `<span class="tl-cost" title="Estimated from reported token usage and a public price table, not an invoice">${fmtCost(e.cost.cost_usd)} est.</span>` : '';
    const tk = e.cost ? `${fmtTokens(e.cost.tokens_in)} in / ${fmtTokens(e.cost.tokens_out)} out` : '';
    return `<div class="tl-item" data-kind="${kind}" data-i="${ev.indexOf(e)}"><span class="tl-dot"></span>
      <div class="tl-card"><button class="tl-head" onclick="this.parentElement.classList.toggle('open')">
        <span class="tl-seq">#${e.seq}</span><span class="tl-type">${esc(e.label)}</span>
        <span class="tl-sum">${esc(e.summary||'')}</span>${cost}<span class="tl-time">${clock(e.ts_utc)}</span>
        <svg class="tl-chev" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      </button>
      <div class="tl-body">
        <div class="tl-kv"><span class="k">timestamp</span><span class="v">${esc(e.ts_utc||'')}</span></div>
        <div class="tl-kv"><span class="k">received</span><span class="v">${esc(e.recv_ts||'')} (recv #${e.recv_seq})</span></div>
        ${e.summary?`<div class="tl-kv"><span class="k">detail</span><span class="v">${esc(e.summary)}</span></div>`:''}
        ${tk?`<div class="tl-kv"><span class="k">tokens</span><span class="v">${tk}</span></div>`:''}
        <div class="tl-kv"><span class="k">record hash</span><span class="v">${esc((e.record_hash||'').slice(0,40))}...</span></div>
      </div></div></div>`;
  }).join('');
  $('#root').innerHTML=`
    <div class="crumb fade"><a href="#/">Overview</a><span class="sep">/</span><a href="#/s/${encodeURIComponent(id)}">${esc(shortId(id))}</a><span class="sep">/</span><span>session ${esc(shortId(sid))}</span></div>
    <div class="page-head fade">
      <div class="eyebrow">Session</div>
      <h1 class="h1">${esc(shortId(sid))}</h1>
      <div class="chips">
        ${live?'<span class="badge live"><span class="bd"></span>Live, unsealed</span>':`<span class="badge ${s.outcome==='failure'?'tampered':'verified'}"><span class="bd"></span>${esc(s.outcome||'sealed')}</span>`}
        <span class="chip">started ${esc(s.started_at?s.started_at.slice(11,19):'')} UTC</span>
        <span class="chip">duration ${dur(s.duration_s)}</span>
        <span class="chip">agent ${esc(s.agent_key||'')}...</span>
        ${metaChips}${chips}
      </div>
    </div>
    <div class="tiles">
      <div class="tile"><div class="k">Duration</div><div class="v">${dur(s.duration_s)}</div></div>
      <div class="tile"><div class="k">Events</div><div class="v">${fmtNum(s.events)}</div></div>
      <div class="tile"><div class="k">Model calls</div><div class="v">${fmtNum(s.model_calls)}</div><div class="x">${fmtNum(s.tool_calls)} tool calls</div></div>
      <div class="tile"><div class="k">Tokens</div><div class="v">${fmtTokens((s.tokens_in||0)+(s.tokens_out||0))}</div><div class="x">${fmtTokens(s.tokens_in)} in / ${fmtTokens(s.tokens_out)} out</div></div>
      <div class="tile accent"><div class="k">Est. cost</div><div class="v">${fmtCost(s.cost_usd)}</div>${s.unpriced_calls?`<div class="x">${s.unpriced_calls} unpriced</div>`:''}</div>
    </div>
    ${ev.length?scrubberHTML(ev,d.sessions||[],sid):''}
    <div class="panel fade" style="background:transparent;border:none">
      <div class="timeline">${items||'<div class="empty-state"><div class="t">No events</div></div>'}</div>
    </div>`;
  if(ev.length) initScrubber(id,sid,ev);
}

/* ---------- replay scrubber ----------
   Step through a run frame by frame, and compare it against another run of the same agent.
   The comparison is the point: a run that broke is only meaningful next to one that worked,
   and the first step where the two diverge is where the debugging actually starts. The
   alignment here is a display aid computed in the browser; `pr diff` remains the version that
   runs over verified bundles and can be trusted as evidence. */
function stepSig(e){
  const t=(e.summary||'').split(' ->')[0].split(':')[0];
  return (e.action_type||'')+'|'+t.trim();
}
function scrubberHTML(ev,sessions,sid){
  const others=(sessions||[]).filter(s=>s.session_id!==sid);
  const opts=others.map(s=>`<option value="${esc(s.session_id)}">${esc(shortId(s.session_id))} · ${esc((s.started_at||'').slice(0,16).replace('T',' '))}</option>`).join('');
  return `<div class="scrub fade">
    <div class="scrub-top">
      <button class="scrub-btn" id="sc-prev" aria-label="previous step">&#9664;</button>
      <button class="scrub-btn" id="sc-next" aria-label="next step">&#9654;</button>
      <span class="scrub-pos" id="sc-pos">step 1 / ${ev.length}</span>
      ${others.length?`<select class="scrub-sel" id="sc-cmp" aria-label="compare with another session">
        <option value="">compare with...</option>${opts}</select>
      <button class="scrub-btn" id="sc-jump" disabled>first deviation</button>`:''}
    </div>
    <input type="range" id="sc-range" min="0" max="${ev.length-1}" value="0" aria-label="replay position">
    <div class="scrub-track" id="sc-track"></div>
    <div class="scrub-frame" id="sc-frame"></div>
  </div>`;
}
function initScrubber(streamId,sid,ev){
  let i=0, diffs=new Set(), firstDiff=-1;
  const pos=$('#sc-pos'), range=$('#sc-range'), track=$('#sc-track'), frame=$('#sc-frame');
  function paint(){
    pos.textContent=`step ${i+1} / ${ev.length}`;
    range.value=String(i);
    track.innerHTML=ev.map((_,n)=>`<span class="scrub-tick${n<=i?' on':''}${diffs.has(n)?' diff':''}"></span>`).join('');
    const e=ev[i];
    const cost = e.cost && e.cost.priced ? ` · ${fmtCost(e.cost.cost_usd)} est.` : '';
    frame.innerHTML=`<div class="h">#${e.seq} ${esc(e.label)}${diffs.has(i)?' <span class="d">(differs)</span>':''}</div>
      <div>${esc(e.summary||'')}${cost}</div>
      <div>${esc(e.ts_utc||'')}</div>
      <div>${esc((e.record_hash||'').slice(0,32))}...</div>`;
    document.querySelectorAll('.tl-item').forEach(el=>{
      const n=Number(el.dataset.i);
      el.classList.toggle('cursor',n===i);
      el.classList.toggle('diff',diffs.has(n));
    });
    const cur=document.querySelector('.tl-item.cursor');
    if(cur) cur.scrollIntoView({block:'nearest'});
  }
  function go(n){ i=Math.max(0,Math.min(ev.length-1,n)); paint(); }
  $('#sc-prev').onclick=()=>go(i-1);
  $('#sc-next').onclick=()=>go(i+1);
  range.oninput=()=>go(Number(range.value));
  // Bound with addEventListener and torn down on navigation. `document.onkeydown = ...`
  // survives the route change, so arrow keys on the overview kept driving a scrubber that
  // was no longer on screen, writing into detached nodes held alive by this closure.
  if(state.scrubKeys){ document.removeEventListener('keydown', state.scrubKeys); }
  state.scrubKeys=(e)=>{
    if(e.target.tagName==='INPUT'||e.target.tagName==='SELECT'||e.target.isContentEditable) return;
    if(e.key==='ArrowLeft'){ e.preventDefault(); go(i-1); }
    else if(e.key==='ArrowRight'){ e.preventDefault(); go(i+1); }
  };
  document.addEventListener('keydown', state.scrubKeys);
  const cmp=$('#sc-cmp');
  if(cmp) cmp.onchange=async()=>{
    diffs=new Set(); firstDiff=-1; $('#sc-jump').disabled=true;
    if(!cmp.value){ paint(); return; }
    try{
      const other=await api('/v1/streams/'+encodeURIComponent(streamId)+'/sessions/'+encodeURIComponent(cmp.value));
      const a=ev.map(stepSig), b=(other.events||[]).map(stepSig);
      for(let n=0;n<a.length;n++){
        if(a[n]!==b[n]){ diffs.add(n); if(firstDiff<0) firstDiff=n; }
      }
      if(b.length<a.length) for(let n=b.length;n<a.length;n++) diffs.add(n);
      $('#sc-jump').disabled=firstDiff<0;
      toast(firstDiff<0?'These two runs took the same path':`First deviation at step ${firstDiff+1}`);
      if(firstDiff>=0) go(firstDiff); else paint();
    }catch(err){ toast('Could not load the comparison run'); }
  };
  const jump=$('#sc-jump');
  if(jump) jump.onclick=()=>{ if(firstDiff>=0) go(firstDiff); };
  paint();
}

/* ---------- alerts ---------- */
const ALERT_EVENTS=[
  ['policy.denied','A policy rule blocked an action your agent attempted. Fires the moment the record arrives, not on the anchor schedule.'],
  ['integrity.tampered','A clean stream now fails verification. The record was altered, reordered, or truncated.'],
  ['integrity.recovered','A tampered stream verifies again.'],
  ['integrity.first_anchor','A stream got its first trusted-time anchor.'],
];
async function renderAlerts(){
  const d=await api('/v1/webhooks'); setConn(true);
  const rows=d.webhooks.length? d.webhooks.map(w=>`
    <div class="row" style="cursor:default;grid-template-columns:1fr auto">
      <div class="c-main"><span class="pri">${esc(w.url)}</span><span class="sec">${esc(w.events==='*'?'all events':w.events)} &middot; added ${ago(w.created_at)}</span></div>
      <button class="tbtn" data-del="${esc(w.webhook_id)}">Delete</button>
    </div>`).join('') : `<div class="empty-state" style="padding:2.5rem 1rem"><div class="t">No alert endpoints</div><div class="d">Add a webhook below to get a signed POST the moment a stream's record stops verifying.</div></div>`;
  const checks=ALERT_EVENTS.map(([e,desc])=>`
    <label style="display:flex;gap:.6rem;align-items:flex-start;margin-bottom:.6rem;cursor:pointer">
      <input type="checkbox" class="ev-cb" value="${e}" checked style="margin-top:.25rem;accent-color:var(--accent)">
      <span><span class="mono" style="font-size:.82rem;color:var(--text-hi)">${e}</span><br><span style="font-size:.8rem;color:var(--text-lo)">${esc(desc)}</span></span>
    </label>`).join('');
  $('#root').innerHTML=`
    <div class="crumb fade"><a href="#/">Overview</a><span class="sep">/</span><span>Alerts</span></div>
    <div class="page-head fade">
      <div class="eyebrow">Integrity alerts</div>
      <h1 class="h1">Get told the moment something goes wrong</h1>
      <p class="lede">Every delivery is a signed POST (HMAC-SHA256 of the body in the <span class="mono" style="font-size:.82rem">X-Provenrail-Signature</span> header), so your receiver can confirm it came from this sink. Policy denials fire at ingest, the instant the record arrives; integrity alerts fire after each anchor.</p>
    </div>
    <div class="panel fade" style="margin-bottom:1.5rem">
      <div class="panel-head"><span class="t">Endpoints</span><span class="t" style="color:var(--text-lo)">${d.webhooks.length} total</span></div>
      <div class="rows" id="hooklist">${rows}</div>
    </div>
    <div class="panel fade"><div class="panel-head"><span class="t">Add endpoint</span></div>
      <div style="padding:1.15rem">
        <div class="field"><label for="whurl">Webhook URL</label><input id="whurl" type="url" placeholder="https://ops.example.com/provenrail" autocomplete="off"></div>
        <div style="margin:.4rem 0 1rem">${checks}</div>
        <div id="wherr" class="gate-err"></div>
        <div id="whkey"></div>
        <button class="btn" id="addhook" style="width:auto;padding:.7rem 1.4rem">Add endpoint</button>
      </div>
    </div>`;
  $('#root').querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>delHook(b.getAttribute('data-del')));
  $('#addhook').onclick=addHook;
}
async function addHook(){
  const url=$('#whurl').value.trim(); const err=$('#wherr');
  err.textContent='';
  if(!/^https?:\/\//.test(url)){ err.textContent='Enter an http(s) URL.'; return; }
  const evs=[...document.querySelectorAll('.ev-cb')].filter(c=>c.checked).map(c=>c.value);
  if(!evs.length){ err.textContent='Pick at least one event.'; return; }
  const all=evs.length===ALERT_EVENTS.length;
  try{
    const h={'Content-Type':'application/json'}; if(state.key) h['Authorization']='Bearer '+state.key;
    const r=await fetch('/v1/webhooks',{method:'POST',headers:h,body:JSON.stringify({url,events:all?['*']:evs})});
    if(!r.ok){ const e=await r.json().catch(()=>({})); throw new Error(e.detail||'failed'); }
    const w=await r.json();
    $('#whkey').innerHTML=`<div class="keybox"><div class="kl">Signing secret, shown once</div><code>${esc(w.secret)}</code><div class="warn">Store it now. Deliveries are signed with it.</div></div>`;
    toast('Endpoint added');
    setTimeout(()=>renderAlerts().then(()=>{ const k=$('#whkey'); }),1400);
  }catch(e){ err.textContent='Could not add: '+esc(e.message); }
}
async function delHook(id){
  try{ const h={}; if(state.key) h['Authorization']='Bearer '+state.key;
    const r=await fetch('/v1/webhooks/'+encodeURIComponent(id),{method:'DELETE',headers:h});
    if(!r.ok) throw new Error(); toast('Endpoint removed'); renderAlerts();
  }catch(_){ toast('Delete failed'); }
}

/* ---------- router ---------- */
async function render(silent){
  const h=location.hash.replace(/^#/,'')||'/';
  const parts=h.split('/').filter(Boolean);
  state.route=h;
  // Tear down the scrubber's key handler before rendering anything else, so arrow keys never
  // drive a view that has left the screen.
  if(state.scrubKeys){ document.removeEventListener('keydown', state.scrubKeys); state.scrubKeys=null; }
  try{
    if(!silent && !state.openMode){ /* show nothing extra */ }
    if(parts[0]==='alerts'){ await renderAlerts(); }
    else if(parts[0]==='s' && parts[2]){ await renderSession(decodeURIComponent(parts[1]),decodeURIComponent(parts[2])); }
    else if(parts[0]==='s' && parts[1]){ await renderStream(decodeURIComponent(parts[1])); }
    else{ await renderOverview(); }
  }catch(e){
    if(e.code===401){ renderGate(silent?'Session expired, reconnect.':''); return; }
    setConn(false);
    if(!silent) $('#root').innerHTML=`<div class="empty-state fade"><div class="ic">!</div><div class="t">Could not load</div><div class="d">${esc(e.message)}. <a href="#/" style="color:var(--accent-text)">Back to overview</a></div></div>`;
  }
}
async function boot(){
  try{ const m=await fetch('/v1/meta').then(r=>r.json()); state.openMode=!!m.open_mode; }catch(_){}
  render(false);
}
window.addEventListener('hashchange',()=>render(false));
boot();
</script>
</body>
</html>
"""
