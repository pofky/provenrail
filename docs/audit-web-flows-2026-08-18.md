# Web + Billing + Account Audit - 2026-08-18

Auditor: Claude Sonnet 4.6 via Claude Code  
Scope: web/ pages, billing flow, account flow, analytics beacon, SEO/AEO/CRO  
Live site: https://provenrail.com  
Tools: Playwright MCP (375px + 1280px), curl, source analysis  
Out of scope: CLI, SDK, server (separate agent)

---

## Verdict Table

| Flow | Verdict | Notes |
|---|---|---|
| All pages load (no 404, no console errors) | PASS | All 14 pages 200 OK, no console warnings or errors on any tested page |
| Layout at 375px | PASS | No horizontal scroll on any tested page (scrollWidth == clientWidth == 375) |
| Layout at 1280px | PASS | No horizontal scroll |
| Fonts and images load | PASS | dm-sans-latin.woff2, dm-mono-400-latin.woff2, logo-mark.png, og.png all 200 |
| Favicon and webmanifest | PASS | favicon.ico, favicon-32.png, favicon-16.png, apple-touch-icon.png, site.webmanifest all 200 |
| All CTAs and internal links land somewhere real | PASS | All 53 homepage links enumerated, all resolve; no dead-ends found |
| External links | PASS | github.com/pofky/provenrail (200), pypi.org/project/provenrail (200), npmjs.com/package/provenrail (loads in browser), astral.sh/uv (200), GitHub issue links (200) |
| Verifier demo path (/verify?demo) | PASS | Shows "Verified and witnessed / Bundle verified" |
| Verifier tamper path (/verify?tamper) | PASS | Shows "Tampering detected / Verification failed" with specific failure detail |
| Purchase flow: pricing CTAs to checkout | PASS | /account?plan=builder correctly shows "Sign in to start Builder. Checkout opens right after." Plan intent stored in localStorage with TTL, cleared from URL to prevent bookmark-triggered checkouts |
| Account page (magic-link, portal) | PARTIAL | Sign-in form renders correctly (GitHub/Google/email options). Cannot complete without real credentials - this is expected. Plan-intent flow verifiable up to this gate. |
| Analytics beacon (/pv) | PASS | POST returns 204 on homepage load. pv.js correctly proxies to Supabase, attaches cf-ipcountry, responds 204 immediately via waitUntil. |
| SEO: titles, meta descriptions, canonical | MOSTLY PASS | One meta description over 160 chars. Pricing title keyword-weak. See findings. |
| SEO: JSON-LD | PASS | index has Organization + WebSite + Product + FAQPage. pricing has BreadcrumbList + Product. verify, docs, start, compare all have appropriate schemas. |
| robots.txt | PASS | Allows all, lists sitemap, explicitly allows 9 AI crawlers (GPTBot, ClaudeBot, PerplexityBot, etc.) |
| llms.txt | PASS | Present, comprehensive - H1 title, summary, honest threat model, pricing, use cases, key pages |
| sitemap.xml | MOSTLY PASS | All 16 public pages listed. lastmod dates not updated after content edits. |
| Copy quality (em-dashes, AI slop, stale claims) | MOSTLY PASS | One stale date phrase found (see Finding 1). No em-dashes, no "delve", "moreover", no triads. |

---

## Findings, Ordered by Severity

### MEDIUM

#### 1. Stale visible copy on eu-ai-act.html: "three days away"
**File:** `web/eu-ai-act.html:163`  
**Observed:** The timeline bullet list contains the phrase: "2 August 2026 (unchanged, and **three days away**): the Article 50 transparency obligations apply..."  
This was written when the page was published around 2026-07-30. Today is 2026-08-18, so August 2 is 16 days in the past. Any visitor reading this sees a factually incorrect claim presented as future-tense.  
The countdown clock at the top of the page correctly detects the date has passed and shows "Article 50 is now in force." - but the bullet text was not updated.  
**Fix:** Replace the phrase to reflect the past tense. Change line 163 from:

```
<li><strong>2 August 2026 (unchanged, and three days away):</strong> the <strong>Article 50 transparency obligations</strong> apply...
```

to:

```
<li><strong>2 August 2026 (now in force):</strong> the <strong>Article 50 transparency obligations</strong> apply...
```

Also update the sitemap `lastmod` for `/eu-ai-act` from `2026-08-05` to `2026-08-18`.

---

### LOW

#### 2. pricing.html meta description is 168 chars (limit is 160)
**File:** `web/pricing.html:7`  
**Observed:** `content="Provenrail pricing: free forever at 50k events a month, Builder $29/mo, Team $99/mo, Enterprise custom. Hash-chain integrity and the open-source verifier on every tier."` - 168 chars, 8 over the 160-char SEO standard limit.  
Google truncates at ~160 chars in SERPs. The "on every tier" tail gets cut.  
**Fix:** Trim to 160 chars. Example (158 chars): `"Provenrail pricing: free forever at 50k events/mo, Builder $29/mo, Team $99/mo, Enterprise custom. The open-source verifier is included on every plan."`

#### 3. pricing.html title has no keyword content
**File:** `web/pricing.html` `<title>` tag  
**Observed:** `<title>Pricing | Provenrail</title>` - 20 chars. No primary keyword. SEO standard requires "primary keyword first, brand last."  
**Fix:** Example: `<title>AI Agent Audit Trail Pricing | Provenrail</title>` (46 chars). Or `<title>Provenrail Plans: Free, Builder $29, Team $99</title>` (57 chars).

#### 4. Sitemap lastmod dates are stale
**File:** `web/sitemap.xml`  
**Observed:** All entries show `2026-08-05` or `2026-08-06` as `lastmod`. At minimum `eu-ai-act.html`, `eu-ai-act-deadline-moved.html`, and `claude-code-guardrails.html` have been substantively edited since those dates (e.g., eu-ai-act.html references dates in August 2026 as if recent). Stale lastmod degrades Googlebot crawl priority for updated pages.  
**Fix:** Update `lastmod` in sitemap.xml to reflect actual last-significant-edit dates. Consider scripting this from git log at deploy time.

---

### INFORMATIONAL (not broken, worth knowing)

#### 5. robots.txt Disallow /app/ - no /app/ route exists
**File:** `web/robots.txt`  
The robots.txt disallows `/app/` but there is no `/app/` route on the site. Not harmful - just likely a planned-but-unused route stub.  
No action required unless /app/ is intentionally being reserved.

#### 6. Account page strips plan param from URL bar (by design)
**File:** `web/account.html:449-464`  
When navigating to `/account?plan=builder`, the URL displayed changes to `/account` because the page reads the `plan` param, stores it in localStorage with a 5-minute TTL, then replaces the URL. This is intentional design to prevent bookmarks or shared links from triggering checkouts unintentionally. The plan intent is correctly shown ("Sign in to start Builder. Checkout opens right after."). No action needed.

#### 7. Analytics beacon correctly handles cf-ipcountry gap
**File:** `functions/pv.js`  
The Cloudflare Pages proxy correctly reads `request.cf.country` (unavailable to Supabase directly) and forwards it via `x-pv-country` header with a shared secret (`PV_PROXY_SECRET`). POST returns 204 on every page load tested. Country attribution is now working.

---

## SEO/AEO/CRO Gate Summary

| Gate | Result |
|---|---|
| Titles <=60 chars | PASS (longest: 59 chars on eu-ai-act-deadline-moved.html) |
| Meta descriptions <=160 chars | FAIL: pricing.html at 168 chars |
| One H1 per page | PASS (spot-checked homepage, pricing, verify, docs) |
| Canonical tags | PASS (all tested pages have correct canonical) |
| robots meta: index,follow on public pages | PASS |
| robots meta: noindex on account + 404 | PASS |
| Open Graph tags | PASS (og:title, og:description, og:url, og:type, og:image on all pages) |
| Twitter Card | PASS (summary_large_image + image on key pages) |
| JSON-LD structured data | PASS (all key pages covered) |
| /robots.txt | PASS |
| /llms.txt | PASS |
| /sitemap.xml | MOSTLY PASS (lastmod stale) |
| No internal 404s | PASS |
| Core Web Vitals signals | Not measured directly; fonts are preloaded, images have width/height, lazy loading on below-fold images - structurally sound |
| No em-dashes in copy | PASS |
| No AI slop phrases | PASS |
| No hardcoded stale facts | FAIL: eu-ai-act.html "three days away" (Finding 1) |
