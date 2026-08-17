"""
Extract and inspect the message body, in particular its links.

Header analysis asks who sent a message. It cannot ask what the message is
trying to get you to do — and for phishing, that is nearly always "click this
link". The single most reliable tell in the whole field is a link whose visible
text names one destination while the underlying href points somewhere else.
That lives in the body, which header-only analysis never sees.

The body is already being pasted: "Show original" in Gmail (and the equivalent
elsewhere) returns the complete MIME message, and Mailgaze previously discarded
everything after the first blank line. This module decodes it instead.

Bodies arrive base64- or quoted-printable-encoded and split across MIME parts,
so decoding goes through the stdlib email package rather than regex over the
raw text. Only text/plain and text/html parts are read; attachments are noted
but never decoded or executed.
"""

import re
from email import message_from_string
from email.message import Message
from html import unescape
from typing import Optional

# Link shorteners hide their destination, which is the point of using one and
# also why phishing likes them.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
    "trib.al", "s.id", "t.ly", "shorte.st", "adf.ly",
}

_ANCHOR = re.compile(
    r"<a\s[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*?>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_TAG = re.compile(r"<[^>]+>")
_BARE_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# A domain-looking token inside link text, e.g. "paypal.com" or "www.bank.co".
_DOMAIN_IN_TEXT = re.compile(
    r"\b((?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,})\b", re.IGNORECASE
)


def _host_of(url: str) -> str:
    """
    Extract the hostname from a URL without importing a URL parser.

    Args:
        url: A URL, possibly without a scheme.

    Returns:
        The lowercased hostname, or "" if none could be read.
    """
    url = url.strip()
    url = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url, flags=re.IGNORECASE)
    url = url.split("/")[0].split("?")[0].split("#")[0]
    url = url.split("@")[-1]  # strip any user:pass@ prefix
    url = url.split(":")[0]   # strip any :port

    return url.strip().lower().rstrip(".")


def _visible_text(html_fragment: str) -> str:
    """Reduce an anchor's inner HTML to the text a reader actually sees."""
    return unescape(_TAG.sub(" ", html_fragment)).strip()


def extract_parts(raw: str) -> dict:
    """
    Decode the text and HTML parts of a raw MIME message.

    Args:
        raw: The complete pasted message, headers and body.

    Returns:
        A dict with "text", "html" and "attachments" keys. Text and HTML are
        empty strings when the message has no body, which is the normal case
        when someone pastes headers alone.
    """
    result = {"text": "", "html": "", "attachments": []}

    try:
        message: Message = message_from_string(raw)
    except Exception:
        return result

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = (part.get_content_type() or "").lower()
        filename = part.get_filename()

        if filename:
            result["attachments"].append(filename)
            continue

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, "replace")
        except Exception:
            continue

        key = "html" if content_type == "text/html" else "text"
        result[key] += decoded

    return result


def extract_links(parts: dict) -> list[dict]:
    """
    Collect every link in the body, with the text shown for it.

    Args:
        parts: The output of extract_parts.

    Returns:
        A list of dicts with "href", "display", "host" and "display_domain".
        display_domain is the domain the link text appears to promise, or ""
        when the text is ordinary wording like "Click here".
    """
    links: list[dict] = []
    seen: set = set()

    for href, inner in _ANCHOR.findall(parts.get("html", "")):
        href = unescape(href).strip()
        if href.lower().startswith(("mailto:", "tel:", "#")):
            continue

        display = _visible_text(inner)
        promised = _DOMAIN_IN_TEXT.search(display)

        key = (href, display)
        if key in seen:
            continue
        seen.add(key)

        links.append({
            "href": href,
            "display": display,
            "host": _host_of(href),
            "display_domain": promised.group(1).lower() if promised else "",
        })

    # Bare URLs in the plain-text part: no display text to disagree with.
    for url in _BARE_URL.findall(parts.get("text", "")):
        key = (url, "")
        if key in seen:
            continue
        seen.add(key)
        links.append({
            "href": url,
            "display": "",
            "host": _host_of(url),
            "display_domain": "",
        })

    return links


def parse_body(raw: str) -> dict:
    """
    Extract everything the body rules need from a raw pasted message.

    Args:
        raw: The complete pasted message.

    Returns:
        A dict with "has_body", "links", "attachments" and "text_length".
    """
    parts = extract_parts(raw)
    links = extract_links(parts)

    return {
        "has_body": bool(parts["text"].strip() or parts["html"].strip()),
        "links": links,
        "attachments": parts["attachments"],
        "text_length": len(parts["text"]) + len(parts["html"]),
    }


def is_deceptive(link: dict) -> bool:
    """
    Decide whether a link's visible text disagrees with where it actually goes.

    The classic phishing link reads "paypal.com" and points at an attacker's
    server. But a legitimate marketing email routinely shows a brand domain
    while routing through a click-tracker, so a bare host comparison produces
    constant false positives. A tracker carries its true destination inside the
    URL; a deceptive link does not mention the promised domain anywhere.

    Args:
        link: One entry from extract_links.

    Returns:
        True if the text promises a domain the URL neither goes to nor names.
    """
    promised = link.get("display_domain", "")
    if not promised:
        return False

    host = link.get("host", "")
    if not host:
        return False

    if _registrable(promised) == _registrable(host):
        return False

    # A redirector that names the promised destination inside the URL is
    # doing what it says, even though the host differs.
    if promised.lower() in link.get("href", "").lower():
        return False

    return True


def _registrable(host: str) -> str:
    """Reduce a hostname to its last two labels for comparison."""
    labels = host.strip().lower().rstrip(".").split(".")

    return ".".join(labels[-2:]) if len(labels) >= 2 else host.strip().lower()
