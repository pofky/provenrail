"""The parts of the site an audit catches and a redesign silently loses.

`test_claims_hygiene.py` pins what the copy may not *say*. This file pins the machinery that
decides whether anyone reads the copy at all: the tags search engines index, the structured data
answer engines lift, and the links that have to resolve. Every check here failed on at least one
page on 2026-09-16, which is why it is a test and not a note.

The rules come from the operator's SEO, CRO and AEO standard, which is not in this tree. Where this
file deviates from that standard it says so in the test that deviates, with the reason, because a
silent deviation is indistinguishable from a page nobody checked.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB = ROOT / "web"

#: Pages deliberately kept out of the index. Both still carry a canonical and a robots meta: the
#: audit has one rule for every page rather than a rule and a list of exceptions to it.
NOINDEX = {"404.html", "account.html"}

#: Sub-pages, in the standard's sense: everything that is not the landing page. They owe a
#: BreadcrumbList pointing back to home, so an answer engine can place them in the site.
LANDING = "index.html"


def pages():
    return sorted(WEB.glob("*.html"))


def _page_ids():
    return [p.name for p in pages()]


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def json_ld(text: str):
    """Every JSON-LD node on a page, flattened out of @graph and top-level arrays."""
    for block in re.findall(r'<script type="application/ld\+json">\s*(.*?)\s*</script>',
                            text, re.S):
        parsed = json.loads(block)
        items = parsed.get("@graph", [parsed]) if isinstance(parsed, dict) else parsed
        for item in items:
            if isinstance(item, dict):
                yield item


def types_on(path: pathlib.Path) -> set[str]:
    return {node.get("@type") for node in json_ld(read(path))}


# ------------------------------------------------------------------ per-page SEO baseline

@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_page_declares_a_canonical(path):
    """Cloudflare Pages serves /docs and /docs.html, and www and pages.dev used to answer too.
    Without a canonical the same page collects ranking signal under several URLs and none of
    them wins."""
    canonicals = re.findall(r'<link rel="canonical" href="(.*?)"', read(path))
    assert len(canonicals) == 1, f"{path.name} has {len(canonicals)} canonical links, expected 1"
    assert canonicals[0].startswith("https://provenrail.com"), canonicals[0]


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_page_has_exactly_one_h1(path):
    headings = re.findall(r"<h1[^>]*>(.*?)</h1>", read(path), re.S)
    assert len(headings) == 1, f"{path.name} has {len(headings)} h1 elements, expected 1"
    assert headings[0].strip(), f"{path.name} has an empty h1"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_title_and_description_fit_what_a_search_result_shows(path):
    """Past the cap Google truncates, and the truncated part is the part that was written last.
    60 and 160 are the standard's numbers, not ours."""
    text = read(path)
    title = re.search(r"<title>(.*?)</title>", text, re.S).group(1).strip()
    assert len(title) <= 60, f"{path.name} title is {len(title)} chars: {title}"
    desc = re.search(r'<meta name="description" content="(.*?)">', text, re.S).group(1).strip()
    assert len(desc) <= 160, f"{path.name} description is {len(desc)} chars"
    assert not desc.lower().startswith("we are"), f"{path.name} description opens with 'We are'"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_page_states_whether_it_should_be_indexed(path):
    robots = re.findall(r'<meta name="robots" content="(.*?)"', read(path))
    assert len(robots) == 1, f"{path.name} has {len(robots)} robots metas, expected 1"
    # noindex,follow rather than plain noindex on the two private pages: the page itself must not
    # rank, and its outbound links to the public site must still be crawled.
    expected = "noindex,follow" if path.name in NOINDEX else "index,follow"
    assert robots[0] == expected, f"{path.name} says robots={robots[0]!r}, expected {expected!r}"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_page_carries_a_complete_social_card(path):
    """A pasted link is often the only impression a page gets. A card missing og:image renders
    as a grey box in Slack and as nothing on X."""
    text = read(path)
    for prop in ("og:title", "og:description", "og:url", "og:type", "og:image"):
        assert re.search(rf'property="{prop}" content="[^"]+"', text), f"{path.name} lacks {prop}"
    card = re.search(r'name="twitter:card" content="(.*?)"', text)
    assert card and card.group(1) == "summary_large_image", f"{path.name} twitter:card"
    assert re.search(r'name="twitter:image" content="[^"]+"', text), f"{path.name} twitter:image"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_page_wraps_its_own_content_in_main(path):
    """Twelve pages put their content as bare siblings of the header and footer. Reader modes and
    extraction pipelines then keep the nav and drop nothing, which is the opposite of useful."""
    assert read(path).count("<main") == 1, f"{path.name} does not have exactly one <main>"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_no_page_uses_a_div_as_a_button(path):
    assert not re.search(r"<div[^>]*onclick", read(path)), f"{path.name} has a div onclick"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_image_declares_alt_text(path):
    """Empty alt is a decision (decorative). A missing alt attribute is an omission."""
    missing = [tag[:80] for tag in re.findall(r"<img\b[^>]*>", read(path)) if "alt=" not in tag]
    assert not missing, f"{path.name} has images with no alt attribute:\n  " + "\n  ".join(missing)


# ------------------------------------------------------------------ AEO structured data

@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_json_ld_block_parses(path):
    """Duplicated from test_claims_hygiene on purpose: this file is what an auditor reads, and a
    schema check that lives only in the claims file gets deleted with the claims file."""
    for block in re.findall(r'<script type="application/ld\+json">\s*(.*?)\s*</script>',
                            read(path), re.S):
        json.loads(block)          # raises with the offset, which is the whole point


def test_the_landing_page_carries_every_schema_the_standard_requires_of_one():
    """Organization, WebSite, a product type and FAQPage. The FAQPage is the one an answer engine
    actually lifts, which is why it is checked for content and not just for presence."""
    found = types_on(WEB / LANDING)
    for required in ("Organization", "WebSite", "SoftwareApplication", "FAQPage"):
        assert required in found, f"index.html has no {required} node (has {sorted(found)})"


def test_the_landing_page_organization_says_who_to_contact():
    org = next(n for n in json_ld(read(WEB / LANDING)) if n.get("@type") == "Organization")
    for field in ("name", "url", "logo", "email"):
        assert org.get(field), f"Organization node has no {field}"
    # The standard also asks for `founder`. It is deliberately absent: the operator trades as a
    # sole trader and is not named anywhere on the site, and a schema field is not the place to
    # publish a private individual's name for the first time. Add it only if he chooses to.
    assert "founder" not in org


def test_the_website_node_does_not_advertise_a_search_endpoint_that_does_not_exist():
    """The standard asks for WebSite with SearchAction. There is no /search on this site, and a
    SearchAction names a URL template a search engine may send a query to, so declaring one would
    advertise a route that answers 404. This test exists so the omission is a recorded decision
    rather than an oversight: ship the SearchAction in the same change that ships the endpoint."""
    site = next(n for n in json_ld(read(WEB / LANDING)) if n.get("@type") == "WebSite")
    assert "potentialAction" not in site
    assert not (WEB / "search.html").exists(), (
        "a search page now exists, so the WebSite node owes a SearchAction")


@pytest.mark.parametrize("path", [p for p in pages() if p.name not in NOINDEX and p.name != LANDING],
                         ids=[p.name for p in pages() if p.name not in NOINDEX and p.name != LANDING])
def test_every_sub_page_places_itself_with_a_breadcrumb(path):
    assert "BreadcrumbList" in types_on(path), f"{path.name} has no BreadcrumbList"


@pytest.mark.parametrize("path", [p for p in pages() if p.name not in NOINDEX],
                         ids=[p.name for p in pages() if p.name not in NOINDEX])
def test_every_indexable_page_declares_when_it_was_last_changed(path):
    """LLMs and search engines both down-rank undated pages, and an undated page about a moving
    vendor default is exactly the page a reader needs a date on."""
    dates = [node.get("dateModified") for node in json_ld(read(path)) if node.get("dateModified")]
    assert dates, f"{path.name} declares no dateModified in any JSON-LD node"
    for value in dates:
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", value), f"{path.name}: {value!r} is not a date"


def test_no_page_invents_a_rating_or_a_review():
    """There are no customers. Review and AggregateRating schema would be a fabricated fact in the
    one place a machine reads as fact, and Google treats self-serving review markup as spam."""
    offences = [p.name for p in pages()
                if types_on(p) & {"Review", "AggregateRating"}
                or "aggregateRating" in read(p)]
    assert not offences, f"review schema on pages with no reviews: {offences}"


#: The questions this product answers, in the wording a person types into ChatGPT or Google. Each
#: has to be answered somewhere in FAQPage markup, self-contained, or the answer cannot be lifted.
#: Add a row when the product starts answering a new question; never delete one to make it pass.
CITABLE_QUESTIONS = {
    # `pr report` is the front door: it answers before the reader has changed anything, so these
    # are the two searches that reach a stranger who has not decided to install a guard yet.
    "how much am i spending on claude code": "index.html",
    "how do i see what my ai agent did": "index.html",
    "does claude code have a spend limit": "index.html",
    "does claude code's auto mode run in headless mode": "index.html",
    "how do i put a dollar cap on a claude code session": "claude-code-guardrails.html",
    "do claude code hooks run in claude -p and in ci": "claude-code-guardrails.html",
}


@pytest.mark.parametrize(("question", "page"), sorted(CITABLE_QUESTIONS.items()))
def test_the_questions_people_ask_are_answered_in_faq_markup(question, page):
    path = WEB / page
    faqs = [n for n in json_ld(read(path)) if n.get("@type") == "FAQPage"]
    assert faqs, f"{page} has no FAQPage node"
    asked = {q["name"].strip().lower().rstrip("?") for f in faqs for q in f["mainEntity"]}
    assert question in asked, f"{page} FAQPage does not ask {question!r}; it asks {sorted(asked)}"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_faq_answer_stands_on_its_own(path):
    """An answer an engine can only quote with the page around it is an answer it will not quote.
    Two cheap proxies for self-containedness: enough words to be a claim, and no opener that
    refers to something above it on the page."""
    for node in json_ld(read(path)):
        if node.get("@type") != "FAQPage":
            continue
        for question in node["mainEntity"]:
            answer = question["acceptedAnswer"]["text"]
            assert len(answer.split()) >= 20, (
                f"{path.name}: answer to {question['name']!r} is too short to cite")
            assert not re.match(r"^(as above|see above|that is|this is why|it does)\b",
                                answer.strip(), re.I), (
                f"{path.name}: answer to {question['name']!r} depends on the text above it")


# ------------------------------------------------------------------ site-wide

def test_no_internal_link_points_at_a_file_that_is_not_there():
    """Checked against the files on disk and against the clean-URL rewrite Cloudflare Pages does
    (/docs serves docs.html), which is how every internal link on this site is written."""
    offences = []
    for path in pages():
        for href in re.findall(r'(?:href|src)="([^"]+)"', read(path)):
            if href.startswith(("http://", "https://", "mailto:", "#", "data:", "javascript:")):
                continue
            target = href.split("#")[0].split("?")[0]
            if not target:
                continue
            on_disk = WEB / target.lstrip("/")
            if on_disk.exists() or (WEB / (target.lstrip("/") + ".html")).exists():
                continue
            if on_disk.is_dir() and (on_disk / "index.html").exists():
                continue
            offences.append(f"{path.name} -> {href}")
    assert not offences, "internal links with no file behind them:\n  " + "\n  ".join(offences)


def test_the_sitemap_lists_every_indexable_page_and_nothing_else():
    text = (WEB / "sitemap.xml").read_text(encoding="utf-8")
    listed = set()
    for loc in re.findall(r"<loc>https://provenrail\.com/?(.*?)</loc>", text):
        listed.add("index.html" if loc == "" else f"{loc}.html")
    indexable = {p.name for p in pages() if p.name not in NOINDEX}
    assert listed == indexable, (
        f"sitemap misses {sorted(indexable - listed)}, lists unknown {sorted(listed - indexable)}")


def test_every_sitemap_entry_carries_a_lastmod():
    text = (WEB / "sitemap.xml").read_text(encoding="utf-8")
    entries = re.findall(r"<url>(.*?)</url>", text, re.S)
    assert entries
    for entry in entries:
        loc = re.search(r"<loc>(.*?)</loc>", entry).group(1)
        lastmod = re.search(r"<lastmod>(.*?)</lastmod>", entry)
        assert lastmod, f"{loc} has no lastmod"
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", lastmod.group(1)), f"{loc}: {lastmod.group(1)}"


#: The primary nav, in order. Ten pages were still shipping the pre-repositioning nav on
#: 2026-09-16 ("How it works", "Compare"), which sent a reader from a legal page to a page the
#: direction memo moved to the footer. One nav or the site is telling two stories.
PRIMARY_NAV = [("/#spend-cap", "Spend cap"),
               ("/claude-code-guardrails", "Guardrails"),
               ("/pricing", "Pricing"),
               ("/docs", "Docs"),
               ("https://github.com/pofky/provenrail", "GitHub"),
               ("/account", "Sign in"),
               ("/start", "Start free")]


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_page_ships_the_same_primary_nav(path):
    block = re.search(r'<div id="nav-links".*?</div>', read(path), re.S)
    assert block, f"{path.name} has no primary nav"
    found = re.findall(r'<a href="([^"]+)"[^>]*>([^<]+)</a>', block.group(0))
    assert found == PRIMARY_NAV, f"{path.name} nav is {found}"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_in_page_anchor_has_something_to_scroll_to(path):
    """A nav link to /#how-it-works that no longer exists lands the reader at the top of the
    homepage with no feedback, which is a 404 nobody can see."""
    text = read(path)
    offences = []
    for href in re.findall(r'href="([^"]*#[^"]+)"', text):
        page, _, fragment = href.partition("#")
        if page == "":
            target = path                 # a bare #frag points at the page it is written on
        elif page == "/":
            target = WEB / LANDING
        else:
            target = WEB / (page.lstrip("/") + ".html")
        if not target.exists():
            continue                      # covered by the broken-link test
        if f'id="{fragment}"' not in read(target):
            offences.append(f"{path.name} -> {href}")
    assert not offences, "links to anchors that do not exist:\n  " + "\n  ".join(offences)


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_every_page_ships_the_same_footer(path):
    """The footer carried three different link sets and, on twenty of twenty-one pages, the
    tagline of the position retired on 2026-09-16. An answer engine crawling any one of those
    pages read the old product description, on every page, whatever the page itself said."""
    index = read(WEB / LANDING)
    for block in (r'        <p class="footer-tagline">.*?</p>\n',
                  r'        <nav class="footer-links" aria-label="Footer links">.*?\n        </nav>\n',
                  r'      <nav class="footer-nav" aria-label="Footer navigation">.*?\n      </nav>\n'):
        canonical = re.search(block, index, re.S)
        assert canonical, "index.html no longer has the block this test copies from"
        assert canonical.group(0) in read(path), (
            f"{path.name} does not ship the homepage's footer; the site is telling two stories")


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_privacy_terms_and_pricing_are_reachable_from_every_page(path):
    text = read(path)
    for required in ("/privacy", "/terms", "/pricing"):
        assert f'href="{required}"' in text, f"{path.name} does not link {required}"


#: Legal pages print a date the reader is entitled to rely on. Its schema twin has to say the
#: same thing: a dateModified of today on a policy last written in June tells a machine the
#: document changed when it did not.
LEGAL_DATES = {"privacy.html": "2026-06-10", "terms.html": "2026-06-08",
               "disclaimer.html": "2026-06-08"}


@pytest.mark.parametrize(("page", "expected"), sorted(LEGAL_DATES.items()))
def test_the_legal_pages_schema_date_matches_the_date_on_the_page(page, expected):
    import datetime

    text = read(WEB / page)
    shown = re.search(r'class="updated">Last updated ([^<]+)<', text).group(1).strip()
    parsed = datetime.datetime.strptime(shown, "%d %B %Y").date().isoformat()
    assert parsed == expected, f"{page} now says 'Last updated {shown}'; update LEGAL_DATES"
    node = next(n for n in json_ld(text) if n.get("@type") == "WebPage")
    assert node["dateModified"] == expected, (
        f"{page} shows {shown} but its schema says {node['dateModified']}")


#: The standard's minimum is five. These nine are the crawlers that actually fetch for an answer
#: engine today; a name removed here is a source of citations turned off.
AI_CRAWLERS = ("GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "PerplexityBot",
               "Google-Extended", "Applebot-Extended", "CCBot", "Bytespider")


def test_robots_txt_allows_the_answer_engines_by_name():
    text = (WEB / "robots.txt").read_text(encoding="utf-8")
    assert "Sitemap: https://provenrail.com/sitemap.xml" in text
    assert re.search(r"User-agent: \*\s*\nAllow: /", text), "robots.txt does not allow by default"
    missing = [bot for bot in AI_CRAWLERS if f"User-agent: {bot}" not in text]
    assert not missing, f"robots.txt does not name {missing}"


def test_llms_txt_follows_the_spec_and_says_when_it_was_written():
    """An llms.txt with a stale price or a retired position is worse than none: it is the file a
    model trusts most and checks least."""
    text = (WEB / "llms.txt").read_text(encoding="utf-8")
    assert text.startswith("# Provenrail"), "llms.txt needs an H1 title first"
    assert re.search(r"^Last updated: \d{4}-\d{2}-\d{2}\.$", text, re.M), "no last-updated line"
    assert re.search(r"^> ", text, re.M), "no blockquote summary"
    for heading in ("## Pricing", "## Key pages", "## Citation-friendly Q&A",
                    "## Preferred citation", "## Honest limits"):
        assert heading in text, f"llms.txt has no {heading} section"
    assert "$9" in text and "$29" not in text and "$99" not in text, "llms.txt price is stale"


def test_every_page_named_in_llms_txt_exists():
    text = (WEB / "llms.txt").read_text(encoding="utf-8")
    missing = []
    for url in set(re.findall(r"https://provenrail\.com/([a-z0-9-]+)", text)):
        if not (WEB / f"{url}.html").exists():
            missing.append(url)
    assert not missing, f"llms.txt points an LLM at pages that do not exist: {missing}"


#: Every visible surface, including the ones a grep over HTML misses. The og:image is the one that
#: bit: it still read "Observability you can take to court" months after the phrase was banned in
#: copy, because a test that reads text cannot read a PNG.
def test_the_social_card_image_is_the_right_size():
    import struct

    header = (WEB / "og.png").read_bytes()[:33]
    width, height = struct.unpack(">II", header[16:24])
    assert (width, height) == (1200, 630), f"og.png is {width}x{height}, not 1200x630"


def test_the_social_card_is_generated_from_a_source_that_is_in_the_tree():
    """The card carries the positioning, so it goes stale exactly when the copy is rewritten. It
    is only re-renderable if the HTML it came from is committed next to it."""
    source = ROOT / "tools" / "og" / "og-card.html"
    assert source.is_file(), "web/og.png has no source; it cannot be regenerated when copy changes"
    text = source.read_text(encoding="utf-8")
    for banned in ("take to court", "audit trail", "agentic logging tool"):
        assert banned not in text.lower(), f"the social card still says {banned!r}"


@pytest.mark.parametrize("path", pages(), ids=_page_ids())
def test_no_page_ships_typography_the_house_style_forbids(path):
    """Checked as characters and as HTML entities. `&hellip;` renders as U+2026 and a scan over
    raw characters walks straight past it, which is how two of them survived."""
    text = read(path)
    forbidden = {"—": "em dash", "–": "en dash", "‘": "smart quote",
                 "’": "smart quote", "“": "smart quote", "”": "smart quote",
                 "…": "ellipsis", " ": "non-breaking space",
                 "&mdash;": "em dash entity", "&ndash;": "en dash entity",
                 "&hellip;": "ellipsis entity", "&nbsp;": "non-breaking space entity",
                 "&rsquo;": "smart quote entity", "&ldquo;": "smart quote entity"}
    found = [name for token, name in forbidden.items() if token in text]
    assert not found, f"{path.name} contains {sorted(set(found))}"
