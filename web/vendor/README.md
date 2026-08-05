# Vendored browser dependencies

Third-party JavaScript this site needs in the browser, served from our own origin instead of a
CDN. Two reasons, and the first is the important one:

- **Supply chain.** `account.html` is the sign-in page. A script host that can change what it
  serves can read a magic-link token out of the page. A pinned file in this repository cannot
  change without a commit.
- **Privacy.** A CDN sees the IP address of every visitor who loads the page. The privacy policy
  states that loading a page contacts no one but us, and that has to be true.

| File | Source | Version |
|---|---|---|
| `supabase-js.mjs` + `sb.mjs` | `@supabase/supabase-js` (MIT) via esm.sh, bundled build | 2.112.0 |
| `node-buffer.mjs`, `node-process.mjs`, `node-events.mjs`, `node-tty.mjs`, `node-async_hooks.mjs` | esm.sh Node builtin shims the bundle imports | as shipped with the above |

Absolute `/node/*.mjs` specifiers in the fetched files were rewritten to relative `./node-*.mjs`
paths so nothing resolves off-origin. To update: refetch the same URLs at the new version, redo
that rewrite, and confirm with a browser run that no request leaves the origin.
