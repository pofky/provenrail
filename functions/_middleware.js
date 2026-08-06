// One canonical host, enforced at the edge.
//
// `_redirects` cannot do this: Cloudflare Pages matches those rules on the PATH only, so a
// host-scoped rule there is silently ignored (it was, which is why this file exists). A
// Pages Function can see the hostname, and unlike an advanced-mode `_worker.js` it still
// composes with `_headers` and `_redirects` instead of replacing them.
//
// Only the two bare aliases are redirected. Per-deploy previews (<hash>.provenrail.pages.dev)
// are a different hostname and stay directly reachable, which is what makes them useful.
const ALIASES = new Set(["www.provenrail.com", "provenrail.pages.dev"]);

export async function onRequest(context) {
  const url = new URL(context.request.url);
  if (ALIASES.has(url.hostname)) {
    url.hostname = "provenrail.com";
    url.protocol = "https:";
    return Response.redirect(url.toString(), 301);
  }
  return context.next();
}
