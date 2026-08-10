/* Provenrail, main.js (minimal) */

// Intersection observer for .reveal elements
(function () {
  if (!('IntersectionObserver' in window)) {
    document.querySelectorAll('.reveal').forEach(el => el.classList.add('visible'));
    return;
  }
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add('visible');
          io.unobserve(e.target);
        }
      });
    },
    { threshold: 0.12 }
  );
  document.querySelectorAll('.reveal').forEach(el => io.observe(el));
})();

// FAQ accordion
document.querySelectorAll('.faq-q').forEach(btn => {
  btn.addEventListener('click', function () {
    const item = this.closest('.faq-item');
    const isOpen = item.classList.contains('open');
    document.querySelectorAll('.faq-item.open').forEach(open => open.classList.remove('open'));
    if (!isOpen) item.classList.add('open');
    this.setAttribute('aria-expanded', String(!isOpen));
  });
});

// Mobile nav toggle
const toggle = document.getElementById('nav-toggle');
const navLinks = document.getElementById('nav-links');
if (toggle && navLinks) {
  toggle.addEventListener('click', () => {
    const open = navLinks.classList.toggle('open');
    toggle.setAttribute('aria-expanded', String(open));
  });
  // Close on outside click
  document.addEventListener('click', e => {
    if (!toggle.contains(e.target) && !navLinks.contains(e.target)) {
      navLinks.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
    }
  });
}

// Copy button
document.querySelectorAll('.copy-btn').forEach(btn => {
  btn.addEventListener('click', function () {
    const pre = this.closest('.code-block').querySelector('pre');
    const text = pre.innerText || pre.textContent;
    navigator.clipboard.writeText(text).then(() => {
      const orig = this.textContent;
      this.textContent = 'Copied';
      setTimeout(() => { this.textContent = orig; }, 1800);
    }).catch(() => {});
  });
});

// Tour: click-to-play tutorial videos (lazy; no bytes load until interaction)
document.querySelectorAll('.tour-card .tour-play').forEach(btn => {
  btn.addEventListener('click', function () {
    const card = this.closest('.tour-card');
    const src = card && card.getAttribute('data-src');
    if (!src) return;
    const v = document.createElement('video');
    v.className = 'tour-video';
    v.src = src;
    v.controls = true;
    v.autoplay = true;
    v.playsInline = true;
    v.preload = 'auto';
    v.setAttribute('aria-label', this.getAttribute('aria-label') || 'Tutorial video');
    this.replaceWith(v);
    v.play().catch(() => {});
  });
});

// First-party, cookieless analytics beacon.
// Stores no cookie, no IP, no device or cross-site identifier, so it needs no consent
// banner under GDPR/ePrivacy. Fails silently and never blocks rendering.
(function () {
  // Same-origin first. The edge proxy at /pv is the only place the visitor's country can be
  // read: Cloudflare fronts our Supabase host but does not forward cf-ipcountry to it, so a
  // beacon posted straight to Supabase can never record where the traffic came from (it
  // recorded NULL for every one of the first 2,204 pageviews). The proxy adds the country at
  // the edge and forwards the body unchanged.
  var ENDPOINT = '/pv';
  var FALLBACK = 'https://jzgamrptvsdxnwtuascx.supabase.co/functions/v1/pageview';
  // One failure of the same-origin path is enough to stop trying it for this page load.
  var proxyDown = false;

  function send(event) {
    try {
      var payload = JSON.stringify({
        e: event,
        p: location.pathname,
        r: document.referrer || null,
        u: new URLSearchParams(location.search).get('utm_source'),
        v: window.innerWidth < 700 ? 'mobile' : 'desktop'
      });
      if (!proxyDown && typeof fetch === 'function') {
        // Same-origin, so there is no CORS to fail and the response IS readable: a broken or
        // missing proxy is detectable here, unlike the cross-origin no-cors path below, and
        // falls back rather than silently dropping the event.
        fetch(ENDPOINT, {
          method: 'POST', body: payload, credentials: 'omit', keepalive: true,
          headers: { 'content-type': 'text/plain;charset=UTF-8' }
        }).then(function (res) {
          if (!res || res.status === 404 || res.status >= 500) { proxyDown = true; direct(payload); }
        }).catch(function () { proxyDown = true; direct(payload); });
        return;
      }
      direct(payload);
    } catch (e) { /* analytics must never break the page */ }
  }

  function direct(payload) {
    try {
      // text/plain is CORS-safelisted, so this needs no preflight. The endpoint parses the
      // body as JSON regardless of the declared content type.
      //
      // fetch with credentials:'omit' is preferred over navigator.sendBeacon, which always
      // issues in credentials mode "include". That forces the endpoint to answer
      // Access-Control-Allow-Credentials, which in turn makes the browser process the
      // Set-Cookie our host's edge attaches (__cf_bm, Domain=supabase.co). Firefox rejects
      // that cookie and logs an error on every single page load. Nothing here wants a
      // cookie: the beacon is deliberately cookieless, so it should not ask to carry one.
      // keepalive keeps the request alive across the navigation a CTA click causes.
      var sent = false;
      if (typeof fetch === 'function') {
        sent = true;
        // no-cors: this is fire-and-forget, we never read the response, and a text/plain POST
        // is a CORS-safelisted simple request so it still arrives intact. Under 'cors' the
        // browser enforces the response headers, so any transient edge error at our host
        // printed a CORS failure in the visitor's console. That is a console error on a real
        // user's page caused by our analytics, which is a bad trade for telemetry we discard.
        fetch(FALLBACK, {
          method: 'POST', body: payload, mode: 'no-cors', credentials: 'omit', keepalive: true,
          headers: { 'content-type': 'text/plain;charset=UTF-8' }
        }).catch(function () {});
      }
      if (!sent && navigator.sendBeacon) {
        navigator.sendBeacon(FALLBACK, new Blob([payload], { type: 'text/plain;charset=UTF-8' }));
      }
    } catch (e) { /* analytics must never break the page */ }
  }

  // Pages with their own scripts (the verifier) report their own events. main.js is deferred,
  // so a module that runs earlier may call this before it exists: those calls queue on
  // window.prQ and are flushed here, which is what makes the /verify?demo deep link countable.
  window.prTrack = send;
  try {
    var q = window.prQ || [];
    window.prQ = { push: send };
    for (var i = 0; i < q.length; i++) send(q[i]);
  } catch (e) { /* ignore */ }

  send('pageview');

  // Conversion intent: which call to action actually gets clicked.
  document.addEventListener('click', function (ev) {
    var a = ev.target && ev.target.closest ? ev.target.closest('a,button') : null;
    if (!a) return;
    var explicit = a.getAttribute('data-ev');
    if (explicit) { send(explicit); return; }
    var href = a.getAttribute('href') || '';
    var label = (a.textContent || '').trim().toLowerCase();
    if (label.indexOf('start free') === 0 || href === '/#pricing') send('cta_start_free');
    else if (href.indexOf('/verify') === 0) send('cta_verify');
    else if (href.indexOf('/docs') === 0 || href.indexOf('/start') === 0) send('cta_docs');
  }, true);
})();

// Keep the shared top nav honest about auth state on every page, not just /account.
// The nav is static HTML, so a signed-in visitor was invited to "Sign in" again everywhere
// else on the site, which reads as if the session had been lost. /account does this properly
// from its live Supabase session; here we only read the token supabase-js already persisted,
// so no SDK is loaded and no request is made. It is a label, never an access decision:
// /account re-checks the real session and corrects this on arrival.
(function () {
  if (location.pathname.indexOf('/account') === 0) return;  // that page paints its own nav
  var link = document.querySelector('.nav-links a[href="/account"]');
  if (!link) return;
  try {
    for (var i = 0; i < localStorage.length; i++) {
      var k = localStorage.key(i);
      if (!k || k.indexOf('sb-') !== 0 || k.indexOf('-auth-token') < 0) continue;
      var t = JSON.parse(localStorage.getItem(k) || 'null');
      // expires_at is seconds since epoch. An expired token still refreshes on /account, so
      // treat it as signed in; only a missing or unparseable token means signed out.
      if (t && (t.access_token || t.refresh_token)) { link.textContent = 'Account'; return; }
    }
  } catch (e) { /* leave the static label alone */ }
})();

/* WCAG 2.1.1 Keyboard: a <pre> that scrolls horizontally is a scrollable region, and a
   scrollable region has to be reachable by keyboard or the content past the right edge
   cannot be read without a pointer. axe flags this as serious; it was on 90 blocks.
   Only blocks that actually overflow get a tab stop, so we do not litter the tab order
   with code that fits. Re-checked on resize, because the same block overflows at 375px
   and does not at 1440px. */
(function () {
  function markScrollable() {
    document.querySelectorAll('pre, table, .scroll-x').forEach(function (el) {
      var overflows = el.scrollWidth > el.clientWidth + 1;
      if (overflows) {
        if (!el.hasAttribute('tabindex')) {
          el.setAttribute('tabindex', '0');
          if (!el.hasAttribute('role')) el.setAttribute('role', 'region');
        }
      } else if (el.getAttribute('tabindex') === '0' && el.getAttribute('role') === 'region') {
        el.removeAttribute('tabindex');
        el.removeAttribute('role');
      }
    });
  }
  markScrollable();
  var t;
  window.addEventListener('resize', function () {
    clearTimeout(t);
    t = setTimeout(markScrollable, 150);
  });
})();
