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
  var ENDPOINT = 'https://jzgamrptvsdxnwtuascx.supabase.co/functions/v1/pageview';

  function send(event) {
    try {
      var payload = JSON.stringify({
        e: event,
        p: location.pathname,
        r: document.referrer || null,
        u: new URLSearchParams(location.search).get('utm_source'),
        v: window.innerWidth < 700 ? 'mobile' : 'desktop'
      });
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
        fetch(ENDPOINT, {
          method: 'POST', body: payload, mode: 'no-cors', credentials: 'omit', keepalive: true,
          headers: { 'content-type': 'text/plain;charset=UTF-8' }
        }).catch(function () {});
      }
      if (!sent && navigator.sendBeacon) {
        navigator.sendBeacon(ENDPOINT, new Blob([payload], { type: 'text/plain;charset=UTF-8' }));
      }
    } catch (e) { /* analytics must never break the page */ }
  }

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
