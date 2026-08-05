# Launch sequence

Written 5 August 2026, from `engine-agentic/docs/distribution-virality-playbook.md`, with
the consumer-app parts (TikTok, ASO, App Store) dropped because this is a developer tool.

The starting position, measured not guessed: 1,691 lifetime pageviews of which roughly
1,600 are our own automated tests, three referrals from Bing, four free signups, zero
paying customers, zero enquiries. PyPI baseline is 2 to 20 real installs a day. This is a
cold start from actual zero, and everything below is sequenced for that.

## The one asset to lead with, everywhere

Every channel should route to `provenrail.com/verify?demo` before it routes to the
homepage. It is a real record verifying in a browser with no signup, no account and no
upload, immediately followed by `?tamper`, the same code over the same record with one
byte changed, going red. Most tools in this space can only assert. We can demonstrate in
about four seconds. That contrast is the whole pitch and it survives being screenshotted.

## Order, and why

Reverse of the obvious. Indie Hackers first, Hacker News second.

1. **Directory and entity profiles (do first, they are slow to propagate).**
   `directory-profiles.txt`. Wikidata and Crunchbase especially: they feed knowledge
   graphs, they take an hour total, and they are close to a hard gate on being named by
   an AI assistant at all. Add each URL to the Organization `sameAs` block in
   `web/index.html` as it goes live.

2. **Indie Hackers.** `launch-indie-hackers.txt`. Honest numbers post. Lower stakes,
   generous audience, and it seeds the founder story that makes the HN post land as a
   person rather than a pitch.

3. **r/ClaudeAI.** `launch-reddit-claudeai.txt`. Our single best-matched audience: they
   already live with the permission-prompt problem daily. Weekday morning US time, and
   clear two hours afterwards to answer every comment. The first two hours decide it.

4. **Show HN.** `launch-show-hn.txt`. Tuesday to Thursday, 8 to 10am Eastern. Post the
   prepared first comment yourself immediately. Then do nothing else for three hours
   except answer. Never argue: agree with the accurate half of a criticism first.

5. **Product Hunt.** `launch-product-hunt.txt`. Tuesday to Thursday 12:01am Pacific.
   Credibility signal, backlink and entity record. Not a growth channel, do not spend
   launch energy here.

6. **r/AI_Agents**, at least three days after r/ClaudeAI and with genuinely different
   text. `launch-reddit-ai-agents.txt`.

## What matters more than any single post

**Brand mentions across many sites are the strongest measured driver of being cited by AI
assistants**, several times stronger than backlinks. That means the goal of each post is
not its traffic spike, it is that the name ends up written down in many places by other
people. A comment that gets quoted is worth more than an upvote.

**Answer-first content.** Each of our guide pages should open with a 40 to 60 word direct
answer to the literal question in its heading. `/eu-ai-act` and `/ai-agent-incidents`
already do this reasonably. Any new page must.

**Original numbers are our unfair advantage and we are not using them.** We own data
nobody else has: measured failure rates from a real concurrency bug, a two-implementation
conformance suite, verification timings across 121,228 records. A short post built around
a proprietary number cannot be paraphrased away by an assistant, and it is the highest
value content we could write next.

**Freshness.** Every guide page now carries a visible last-updated date wired to its real
last change. Keep it true. Assistants weight recent content heavily and a stale date is
worse than none.

## What not to spend time on

- `llms.txt`: measured null effect in three large independent studies. Ours exists. Never
  strategise about it again.
- FAQ schema as a citation lever: slightly negative in the largest study. Keep the FAQ
  content, which does help, and expect nothing from the markup beyond Google rich results.
- Backlink building: weak correlation with AI citation. Mentions matter, links much less.
- Product Hunt as growth. See above.
- Bitcoin anchoring, for now. It is a real differentiator and it answers a question no
  prospect has reached yet. Build it when one asks who they have to trust for the
  timestamp, which is a buying signal, and then it closes a specific deal.

## How to know if it worked

Stop counting pageviews as the primary measure. Weekly, ask ChatGPT, Claude, Perplexity
and Google AI the twenty questions a buyer would actually ask ("how do I stop Claude Code
running rm -rf", "how do I prove what an AI agent did", "AI agent audit trail tools",
"EU AI Act Article 12 logging tools") and log who gets named. That number moving is the
leading indicator. Signups follow it, not the other way round.

The real threshold to watch for is one unprompted enquiry from someone we did not tell
about it. Everything before that is still a cold start.
