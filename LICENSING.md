# Licensing

Provenrail is **open-core, dual-licensed**. The split is deliberate: maximize adoption and
independent verifiability of the client and format (so Provenrail records are trusted and the
format spreads), while keeping a commercial lever on the server.

## What is licensed how

| Component | Paths | License |
|---|---|---|
| Client SDK, CLI, verifier (`pr-verify`), bundle format, spec, web verifier | everything EXCEPT `src/provenrail/server/**` (notably `src/provenrail/sdk.py`, `verifier/`, `tlog.py`, `scitt.py`, `cbor.py`, `redaction.py`, `easy.py`, `integrations/`, `web/verify.js`, `SPEC.md`) | **MIT** (`LICENSE`) |
| Server / sink (the hosted ingest, anchoring, transparency-log, dashboard, API) | `src/provenrail/server/**` | **AGPL-3.0-or-later** (`LICENSE-AGPL`) |

Rationale:
- **MIT on the client + verifier + spec** removes every barrier to verifying a Provenrail record
  and to embedding the SDK. Wide, frictionless verification is the standard-capture moat
  (see `MOAT.md`): a record anyone can check, with a tool under a permissive license, is the point.
- **AGPL on the server** means anyone may self-host and modify it, but a company that runs a
  modified Provenrail server as a network service must release their changes under the AGPL.
  Organizations that do not want that obligation can buy a commercial license.

## Commercial license (the revenue lever)

If you want to run or embed the Provenrail server without AGPL obligations (proprietary internal
deployment, closed-source SaaS resale, OEM), a commercial license is available. This is a pure IP
transaction: no hosting of your data by us, no ongoing service. Contact: hello@provenrail.com.

## Contributions

By contributing you agree your contribution may be distributed under both the MIT and AGPL terms
above as applicable to the path you touch. A formal CLA may be introduced before the first
commercial license is sold.

## Note on the copyright holder

The copyright line reads "Provenrail" pending formal entity formation. Until then the work is held
by the sole proprietor operating under that name; it can be reassigned to the company on
incorporation without affecting the license grants already made.
