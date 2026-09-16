# Launch baselines, day 0

Read on 2026-09-16, before anything is posted. Every number here is a measurement, so that
the launch is judged against what was true before it rather than against a memory of it.
The falsifier that uses these is `docs/direction-2026-09-16.md` section 6.

| Signal | Value | Source |
|---|---|---|
| GitHub stars | 0 | `gh api repos/pofky/provenrail` |
| Forks | 0 | same |
| Watchers | 0 | same |
| Unique repo views, 14d | 5 (9 total) | `traffic/views` |
| Unique cloners, 14d | 88 (348 total) | `traffic/clones` |
| Repo referrers, 14d | github.com 1 unique, provenrail.com 1 unique | `traffic/popular/referrers` |
| Site pageviews, all time | 2,618 | production `pageviews` |
| Site pageviews, 30d | 311 | same |
| Referred pageviews, 30d | 36, all search (bing 16, google 14, chatgpt 5, brave 1) | same |
| Social referrals, ever | 0 | same |
| Profiles | 4, all the operator's | production `profiles` |
| Paying customers | 0 | `profiles.subscription_status = 'active'` |
| Anchor accounts | 1, the operator's | production `anchor_accounts` |
| Verifier runs | 23 | `pageviews` where `event = 'verify_run'` |
| Plugin directory installs | not listed yet | claude.com/plugins |

## One correction to the falsifier, found by measuring it

Section 6 sets a kill criterion of "unique 14-day cloners below 70", inherited from
`Marketing/launch-week-checklist.txt` where the baseline was 23. **It reads 88 today, with
nothing posted and no humans involved.** Cloners are package mirrors, CI and scrapers; the
number moved because releases were published, not because anyone arrived. A criterion that is
already passed on day 0 cannot falsify anything, and would have been read later as evidence
the launch worked.

So the honest pair to judge on 2026-10-31 is:

- **Plugin directory installs**, which the directory publishes per plugin and which no mirror
  inflates.
- **Unique repo VIEWS**, 5 today. Views need a browser; clones do not.

Cloners stay in the table because dropping a number after seeing it is how a baseline becomes
a story, but they are not a criterion. Star count is kept for the same reason and is equally
weak: it measures approval of a post, not use of a tool.
