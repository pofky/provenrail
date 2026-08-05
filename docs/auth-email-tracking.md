# Sign-in emails are being tracked, and Brevo cannot turn it off

**Status:** mitigated and PARKED, 2026-08-05. Anonymous tracking is on, which settles the
privacy question. What remains is a deliverability nuisance, not a security hole. Revisit if
sign-in complaints appear or we start selling into companies. Do not migrate provider before
then: it is work that buys little at zero users.
**Found:** 2026-08-05, by receiving a real sign-in email in a disposable inbox and reading it.

## What is happening

Every Provenrail sign-in email goes out through Brevo (our Supabase Auth SMTP relay). Brevo
rewrites the sign-in link to its own tracking domain and attaches an open-tracking pixel. The
link a user clicks looks like this:

    https://bbbcebjd.r.af.d.sendibt2.com/tr/cl/QbegSWzLRHyaOsmSBUpsfGloVO385Dud...

which 302s to `supabase.co/auth/v1/verify`, which lands on `provenrail.com/account`. The
sign-in works. That is not the problem.

The problems are:

1. **A third party logs our users' sign-in behaviour.** Brevo records when each person opens
   their sign-in email and when they click it, against their email address.
2. **A one-time authentication token transits a tracker's URL space.** It should go from our
   mail to our domain and nowhere else.
3. **Link rewriting to an unrelated domain is a phishing signal.** Some mail security products
   rewrite or block it, which turns into "I never got my sign-in link".

## What I got wrong first

I originally wrote that this was one setting in the Brevo dashboard under
Transactional > Settings > Tracking. That path does not exist (Transactional only has Email
with Real time, Statistics, Logs and Templates), and more importantly the outcome is not
available on Brevo at all.

## What Brevo actually offers

**You can anonymise it. You cannot disable it.** Brevo has an "Anonymous email tracking"
setting, reached from the account dropdown under Settings, in the transactional email tracking
section. Turning it on stops opens and clicks being linked to individual recipients.

It does **not** stop the link being rewritten through `sendibt2.com`. Disabling click tracking
on transactional SMTP is a long-standing open feature request, not a setting:
<https://community.brevo.com/t/no-way-to-disable-by-option-tracking-in-transactional-e-mail/201>

So anonymising fixes problem 1 and leaves problems 2 and 3 exactly where they are.

Brevo's per-message `X-Mailin-Track` header is not a way out either: Supabase Auth gives no
control over SMTP headers, so we cannot set it.

## Measured after anonymous tracking was switched on (2026-08-05)

Sent a real sign-in link to a disposable inbox and read the raw message.

- The wrapping host changed from `bbbcebjd.r.af.d.sendibt2.com` to
  `bbbcebjd.r.bh.d.sendibt3.com`, presumably the anonymised cluster.
- The open-tracking pixel is **still present**.
- The sign-in link is **still rewritten**: 4 links in the message, all on the tracker host,
  and no direct `supabase.co` or `provenrail.com` URL anywhere in the email.
- Sign-in still works: 302 tracker -> 303 `supabase.co/auth/v1/verify` -> 200
  `provenrail.com/account`, signed in.

So anonymising removed the link between tracking and the individual, which was worth doing,
and left the auth token still transiting a third-party redirect and the phishing-signal
rewrite untouched. Those only go away by changing provider.

## Why this is parked rather than fixed

Two of the three concerns above do not survive scrutiny:

- "A third party sees the auth token" is true of **any** SMTP relay. The token is in the email
  body whoever sends it. Changing provider does not change that.
- The privacy concern was the real one, and anonymous tracking addressed it.

What genuinely remains is deliverability. Corporate mail security rewrites or blocks links to
unfamiliar tracking domains, and some scanners pre-fetch them. A pre-fetched one-time sign-in
link is consumed before the user clicks it, so they see "invalid or expired link" and cannot
sign in. That is a real failure mode, and it lands mostly on enterprise inboxes.

At zero users that is a nuisance worth watching, not a migration worth doing.

## The fix, when it is worth doing

Move authentication email to a relay that lets us turn click tracking off. This is a Supabase
Auth SMTP config change (host, port, user, password) plus DNS records for the new sender, and
it removes the tracker from the chain entirely rather than anonymising it.

Candidates, all of which support disabling click tracking:

| Provider | Free tier | Notes |
|---|---|---|
| Resend | 3,000/mo, 100/day | Click tracking **off by default**. Simplest fit for our volume. |
| Amazon SES | 3,000 msg/mo trial, then ~$0.10/1,000 | Cheapest at scale, most setup. |
| Postmark | 100/mo free, then $15/mo | Strong transactional deliverability reputation. |
| Mailgun | pay as you go | Tracking is a per-domain toggle. |

Our volume is sign-in links only, so any free tier covers it.

**Recommendation: Resend.** Click tracking is off by default, so the failure mode we just hit
cannot silently come back, and the free tier covers us with room. Brevo stays where it is for
anything marketing.

## Interim, while the decision is open

- The privacy page discloses this in the sub-processor list, naming Brevo and stating plainly
  that opens and clicks are recorded and that we are turning it off. `web/privacy.html`.
- `tests/test_web_no_third_party.py` fails if a processor we use is missing from that page.
- GitHub and Google sign-in do not touch email at all, so they are unaffected.

## When it is done

Send a sign-in link to a disposable inbox, read the raw message, and confirm the link points
straight at `supabase.co`/`provenrail.com` with no intermediate host. Then delete the tracking
sentences from the Brevo entry on the privacy page.
