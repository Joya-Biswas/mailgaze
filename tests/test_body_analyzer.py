"""
Tests for body extraction and link inspection.

The body arrives base64- or quoted-printable-encoded and split across MIME
parts, so these check decoding as well as the link logic. The important
behaviour is the deception test: it has to catch a link whose text disagrees
with its destination, without flagging the click-trackers that ordinary
marketing email is full of.
"""

import base64

from app.analyzer import analyze
from app.body_analyzer import (
    extract_links,
    extract_parts,
    is_deceptive,
    parse_body,
)
from app.parser import parse_headers

HEADERS = (
    "Received: from mail.sender.test (mail.sender.test [45.33.32.156])\n"
    "\tby mx.google.com with ESMTPS id x; Fri, 7 Aug 2026 14:27:00 -0700\n"
    "From: Sender <hello@sender.test>\n"
    "Subject: Hello\n"
    "To: you@gmail.com\n"
)


def message(body: str, content_type: str = "text/html") -> str:
    return f"{HEADERS}Content-Type: {content_type}; charset=\"UTF-8\"\n\n{body}\n"


class TestExtractParts:
    """Test cases for extract_parts."""

    def test_plain_body(self):
        parts = extract_parts(message("Just some words.", "text/plain"))

        assert "Just some words." in parts["text"]
        assert parts["html"] == ""

    def test_html_body(self):
        parts = extract_parts(message("<p>Hi</p>"))

        assert "<p>Hi</p>" in parts["html"]

    def test_base64_body_is_decoded(self):
        encoded = base64.b64encode(b"<p>Secret offer</p>").decode()
        raw = (
            HEADERS
            + 'Content-Type: text/html; charset="UTF-8"\n'
            + "Content-Transfer-Encoding: base64\n\n"
            + encoded
            + "\n"
        )

        assert "Secret offer" in extract_parts(raw)["html"]

    def test_quoted_printable_body_is_decoded(self):
        raw = (
            HEADERS
            + 'Content-Type: text/plain; charset="UTF-8"\n'
            + "Content-Transfer-Encoding: quoted-printable\n\n"
            + "Pay =E2=82=AC100 now\n"
        )

        assert "100 now" in extract_parts(raw)["text"]

    def test_headers_only_paste_has_no_body(self):
        assert parse_body(HEADERS)["has_body"] is False


class TestExtractLinks:
    """Test cases for extract_links."""

    def test_anchor_href_and_text(self):
        parts = extract_parts(message('<a href="https://a.test/x">Click me</a>'))

        links = extract_links(parts)

        assert links[0]["href"] == "https://a.test/x"
        assert links[0]["display"] == "Click me"
        assert links[0]["host"] == "a.test"

    def test_display_domain_is_captured(self):
        parts = extract_parts(message('<a href="https://evil.test/x">paypal.com</a>'))

        assert extract_links(parts)[0]["display_domain"] == "paypal.com"

    def test_nested_markup_in_link_text(self):
        parts = extract_parts(
            message('<a href="https://a.test"><span><b>Shop</b> now</span></a>')
        )

        assert "Shop" in extract_links(parts)[0]["display"]

    def test_mailto_is_ignored(self):
        parts = extract_parts(message('<a href="mailto:x@y.test">mail us</a>'))

        assert extract_links(parts) == []

    def test_bare_urls_in_plain_text(self):
        parts = extract_parts(message("Visit https://plain.test/page today", "text/plain"))

        links = extract_links(parts)

        assert links[0]["host"] == "plain.test"

    def test_port_and_credentials_are_stripped_from_host(self):
        parts = extract_parts(
            message('<a href="http://user:pw@host.test:8080/p">go</a>')
        )

        assert extract_links(parts)[0]["host"] == "host.test"


class TestIsDeceptive:
    """The core judgement: does the text disagree with the destination?"""

    def test_text_naming_another_domain_is_deceptive(self):
        link = {"display": "paypal.com", "display_domain": "paypal.com",
                "host": "evil-login.tk", "href": "http://evil-login.tk/paypal"}

        assert is_deceptive(link) is True

    def test_matching_domain_is_fine(self):
        link = {"display": "paypal.com", "display_domain": "paypal.com",
                "host": "www.paypal.com", "href": "https://www.paypal.com/home"}

        assert is_deceptive(link) is False

    def test_click_tracker_naming_its_destination_is_fine(self):
        """Marketing mail routes through trackers; that isn't deception."""
        link = {
            "display": "paypal.com",
            "display_domain": "paypal.com",
            "host": "click.mailer.test",
            "href": "https://click.mailer.test/r?url=paypal.com/home",
        }

        assert is_deceptive(link) is False

    def test_ordinary_link_text_is_not_judged(self):
        link = {"display": "Click here", "display_domain": "",
                "host": "anything.test", "href": "https://anything.test"}

        assert is_deceptive(link) is False


class TestLinkRulesInAnalyzer:
    """R17-R20 wiring."""

    def rules(self, body_html):
        findings, _ = analyze(parse_headers(message(body_html)))
        return [f.rule_id for f in findings]

    def test_deceptive_link_is_high(self):
        findings, _ = analyze(parse_headers(
            message('<a href="http://evil-login.tk/p">paypal.com</a>')
        ))
        r17 = [f for f in findings if f.rule_id == "R17"]

        assert r17 and r17[0].severity == "high"

    def test_punycode_link_is_flagged(self):
        assert "R18" in self.rules('<a href="http://xn--pypal-4ve.com/x">login</a>')

    def test_bare_ip_link_is_flagged(self):
        assert "R19" in self.rules('<a href="http://45.33.32.156/login">verify</a>')

    def test_shortener_is_flagged(self):
        assert "R20" in self.rules('<a href="https://bit.ly/3xYz">offer</a>')

    def test_ordinary_link_raises_nothing(self):
        rules = self.rules('<a href="https://sender.test/news">Read our newsletter</a>')

        assert not [r for r in rules if r in ("R17", "R18", "R19", "R20")]

    def test_headers_only_paste_raises_no_link_rules(self):
        findings, _ = analyze(parse_headers(HEADERS))

        assert not [f for f in findings if f.rule_id in ("R17", "R18", "R19", "R20")]
