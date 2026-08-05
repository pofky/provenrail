"""The privacy page promises that loading a page makes no third-party request. That is a claim
about the site's markup, so it is asserted against the markup rather than trusted.

It has been wrong twice: fonts were loaded from Google, and the sign-in page pulled its Supabase
client from a script CDN. Both are the kind of change that gets made for convenience and is
never noticed again, which is exactly what a test is for.
"""

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parent.parent / "web"

#: Hosts a page is allowed to reach: our own domain, and our own backend, which the privacy page
#: discloses by name. Anything else would make the published sentence false.
ALLOWED_HOSTS = ("provenrail.com", "supabase.co")

#: `rel` values on <link> that describe a URL rather than fetch one (canonical, og:url and
#: friends). Absolute self-references there are correct and are not requests.
NON_FETCHING_REL = ("canonical", "alternate", "me", "author", "license", "prev", "next")

#: Attributes whose value the browser fetches on its own, without the visitor doing anything.
FETCHED_ATTRS = ("src", "href", "srcset", "poster", "data-src")

PAGES = sorted(WEB.glob("*.html"))


def _urls_the_browser_fetches(html: str) -> list[str]:
    urls: list[str] = []
    # Attributes that trigger a fetch, minus <a href>, which is a link the visitor chooses.
    for m in re.finditer(r'<(\w+)\s+([^>]*)>', html):
        tag, attrs = m.group(1).lower(), m.group(2)
        rel = (re.search(r'\brel\s*=\s*"([^"]*)"', attrs) or re.match("", "")).group(0)
        rel = re.sub(r'^rel\s*=\s*"|"$', "", rel).lower()
        for attr in FETCHED_ATTRS:
            if tag == "a" and attr == "href":
                continue
            if tag == "link" and attr == "href" and rel in NON_FETCHING_REL:
                continue
            for am in re.finditer(rf'\b{attr}\s*=\s*"([^"]*)"', attrs):
                urls.append(am.group(1))
    # ES module specifiers and CSS url()/@import inside inline blocks.
    urls += re.findall(r'from\s+["\']([^"\']+)["\']', html)
    urls += re.findall(r'\burl\(\s*["\']?([^"\')]+)', html)
    urls += re.findall(r'@import\s+["\']([^"\']+)["\']', html)
    return urls


def _offending(urls) -> list[str]:
    bad = []
    for u in urls:
        u = u.strip()
        if not u.startswith(("http://", "https://", "//")):
            continue                                   # relative: our own origin
        host = re.sub(r'^(https?:)?//', '', u).split("/")[0].lower()
        if not any(host == a or host.endswith("." + a) for a in ALLOWED_HOSTS):
            bad.append(u)
    return bad


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_a_page_fetches_nothing_from_a_third_party(page):
    bad = _offending(_urls_the_browser_fetches(page.read_text(encoding="utf-8")))
    assert not bad, (
        f"{page.name} fetches from a third party: {bad}. The privacy page states that loading a "
        f"page makes no third-party request; vendor the asset under web/ or amend the promise.")


def test_the_stylesheet_fetches_nothing_from_a_third_party():
    css = (WEB / "styles.css").read_text(encoding="utf-8")
    urls = re.findall(r'\burl\(\s*["\']?([^"\')]+)', css) + \
        re.findall(r'@import\s+["\']([^"\']+)["\']', css)
    assert not _offending(urls), _offending(urls)


def test_vendored_modules_resolve_locally():
    """A vendored bundle that still imports from the CDN it came from is not vendored. The
    fetched files carry absolute /node/*.mjs specifiers, which resolve against whatever origin
    serves them."""
    vendor = WEB / "vendor"
    assert vendor.is_dir(), "web/vendor is where third-party browser code lives"
    for mod in vendor.glob("*.mjs"):
        text = mod.read_text(encoding="utf-8")
        absolute = re.findall(r'(?:from|import)\s*["\'](/[^"\']+)["\']', text)
        assert not absolute, f"{mod.name} imports {absolute}, which resolves off this directory"
        assert not _offending(re.findall(r'(?:from|import)\s*["\']([^"\']+)["\']', text))


def test_the_self_hosted_fonts_are_present_and_licensed():
    """The @font-face rules name files that have to exist, and the OFL requires the license text
    to travel with the fonts."""
    css = (WEB / "styles.css").read_text(encoding="utf-8")
    referenced = set(re.findall(r"url\('(/fonts/[^']+)'\)", css))
    assert referenced, "styles.css should declare the self-hosted faces"
    for ref in referenced:
        assert (WEB / ref.lstrip("/")).is_file(), f"{ref} is referenced but not shipped"
    licence = WEB / "fonts" / "OFL.txt"
    assert licence.is_file() and "Open Font License" in licence.read_text(encoding="utf-8")


#: Every third party that touches personal data has to be named on the privacy page. This list is
#: the one we actually use; adding a service without adding it here is the failure mode, so the
#: test exists to make that a red build rather than a discovery during an audit.
DISCLOSED_PROCESSORS = ("Supabase", "Polar", "Brevo", "GitHub", "Google")


@pytest.mark.parametrize("name", DISCLOSED_PROCESSORS)
def test_the_privacy_page_names_every_processor_we_use(name):
    """Brevo delivers every sign-in email and was not on this page. A processor you do not name is
    one a reader cannot object to, which is the whole point of naming them."""
    text = (WEB / "privacy.html").read_text(encoding="utf-8")
    assert name in text, (
        f"{name} processes personal data for us but is not disclosed on the privacy page")
