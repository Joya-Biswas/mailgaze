"""
Tests for the trust boundary on Authentication-Results, and for the rules that
depend on it.

The threat these cover: a sender controls every header in the message they
send, so anyone can write "spf=pass" into their own mail. A result only means
something if the server that received the message is the one that recorded it.
"""

from app.analyzer import analyze, detect_display_name_impersonation
from app.auth_checker import evaluate_auth, registrable_domain
from app.parser import parse_headers


def build(headers: str) -> dict:
    """Parse a header block written inline in a test."""
    return parse_headers(headers.strip() + "\n")


class TestRegistrableDomain:
    """Test cases for registrable_domain."""

    def test_reduces_to_last_two_labels(self):
        assert registrable_domain("mx.google.com") == "google.com"
        assert registrable_domain("a.b.c.example.org") == "example.org"

    def test_leaves_bare_domain_alone(self):
        assert registrable_domain("example.com") == "example.com"

    def test_normalizes_case_and_trailing_dot(self):
        assert registrable_domain("MX.Example.COM.") == "example.com"

    def test_handles_empty_and_single_label(self):
        assert registrable_domain("") == ""
        assert registrable_domain("localhost") == "localhost"


class TestEvaluateAuth:
    """Test cases for evaluate_auth."""

    def test_no_headers_is_untrusted_and_missing(self):
        result = evaluate_auth([], "mx.gmail.com")

        assert result["trusted"] is False
        assert result["spf"]["result"] == "missing"
        assert "no Authentication-Results" in result["reason"]

    def test_authserv_matching_receiver_is_trusted(self):
        result = evaluate_auth(
            ["mx.gmail.com; spf=pass; dkim=pass; dmarc=pass"], "mx.gmail.com"
        )

        assert result["trusted"] is True
        assert result["authserv"] == "mx.gmail.com"
        assert result["spf"]["result"] == "pass"

    def test_subdomain_of_receiver_is_trusted(self):
        """The stamping name and the receiving host share a registrable domain."""
        result = evaluate_auth(
            ["mx.google.com; spf=pass"], "mx4.smtp.google.com"
        )

        assert result["trusted"] is True

    def test_authserv_from_another_domain_is_not_trusted(self):
        """The forged case: sender names a server that did not receive the mail."""
        result = evaluate_auth(
            ["mx.gmail.com; spf=pass; dkim=pass; dmarc=pass"], "mx.evil-relay.tk"
        )

        assert result["trusted"] is False
        assert "not the receiving server" in result["reason"]

    def test_no_receiving_host_is_not_trusted(self):
        """With no Received chain there is nothing to anchor trust to."""
        result = evaluate_auth(["mx.gmail.com; spf=pass"], None)

        assert result["trusted"] is False

    def test_only_topmost_header_is_read(self):
        """Headers below the top arrived with the message and are not read."""
        result = evaluate_auth(
            [
                "mx.gmail.com; spf=fail",
                "mx.gmail.com; spf=pass",
            ],
            "mx.gmail.com",
        )

        assert result["spf"]["result"] == "fail"
        assert result["extra_headers"] == 1


class TestForgedAuthIsCaught:
    """End-to-end: a message asserting its own authentication must not pass."""

    FORGED = """
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass; dmarc=pass
Received: from mail.spam-sender.tk (mail.spam-sender.tk [198.51.100.50])
\tby mx.evil-relay.tk with ESMTP id abc123
\tfor <user@gmail.com>; Mon, 15 Jan 2024 10:45:25 +0000
Date: Mon, 15 Jan 2024 10:45:00 +0000
Message-ID: <x@spam-sender.tk>
Subject: Your invoice is ready
From: "PayPal Service Center" <noreply@spam-sender.tk>
To: user@gmail.com
"""

    INJECTED = """
Authentication-Results: mx.gmail.com; spf=fail; dkim=fail; dmarc=fail
Received: from mail.spam-sender.tk (mail.spam-sender.tk [198.51.100.50])
\tby mx.gmail.com with ESMTP id abc123
\tfor <user@gmail.com>; Mon, 15 Jan 2024 10:45:25 +0000
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass; dmarc=pass
Date: Mon, 15 Jan 2024 10:45:00 +0000
Message-ID: <x@spam-sender.tk>
Subject: Your invoice is ready
From: "Billing" <noreply@spam-sender.tk>
To: user@gmail.com
"""

    def test_forged_authserv_does_not_yield_a_clean_verdict(self):
        findings, verdict = analyze(build(self.FORGED))
        rule_ids = [f.rule_id for f in findings]

        assert verdict != "Likely Legitimate"
        assert "R11" in rule_ids  # unverifiable claim
        assert "R1" in rule_ids   # and therefore not passing

    def test_injected_second_header_is_reported(self):
        findings, verdict = analyze(build(self.INJECTED))
        rule_ids = [f.rule_id for f in findings]

        assert "R12" in rule_ids
        assert verdict != "Likely Legitimate"


class TestKnownLimitation:
    """
    Documents the ceiling of a paste-based tool. This is a characterization
    test: it records what the code currently does, not what it should do.

    The trust check compares the authserv-id against the "by" host of the
    topmost Received hop — but both lines are part of the pasted text, so an
    attacker who forges the Received line to agree with the
    Authentication-Results line defeats it. A header genuinely written by Gmail
    and one typed by an attacker are byte-for-byte identical; the information
    that would separate them is not in the text at all.

    Closing this needs a check against something the sender does not control:
    live SPF/DMARC evaluation via DNS, or DKIM signature verification. When
    either lands, this test should start failing and be replaced.
    """

    CONSISTENT_FORGERY = """
Authentication-Results: mx.gmail.com; spf=pass smtp.mailfrom=billing@secure-billing.com; dkim=pass header.d=secure-billing.com; dmarc=pass header.from=secure-billing.com
Received: from mail.secure-billing.com (mail.secure-billing.com [198.51.100.50])
\tby mx.gmail.com with ESMTPS id abc123
\tfor <user@gmail.com>; Mon, 15 Jan 2024 10:45:25 +0000
Date: Mon, 15 Jan 2024 10:45:00 +0000
Message-ID: <inv-88213@secure-billing.com>
Subject: Invoice 88213 is ready for review
From: Accounts Receivable <billing@secure-billing.com>
Return-Path: <billing@secure-billing.com>
To: user@gmail.com
"""

    def test_internally_consistent_forgery_is_not_detected(self):
        """A forgery that forges the Received hop too currently passes clean."""
        findings, verdict = analyze(build(self.CONSISTENT_FORGERY))

        # Recorded, not endorsed. See the class docstring.
        assert verdict == "Likely Legitimate"
        assert findings == []


class TestDisplayNameImpersonation:
    """R2 should report claimed identities, not every name that differs."""

    def test_ordinary_personal_name_is_not_flagged(self):
        assert detect_display_name_impersonation("John Smith", "example.com") == ""

    def test_ordinary_role_name_is_not_flagged(self):
        assert detect_display_name_impersonation("IT Helpdesk", "corp.example.com") == ""

    def test_brand_word_inside_another_word_is_not_flagged(self):
        assert detect_display_name_impersonation("Purchase Team", "shop.example.com") == ""

    def test_brand_on_matching_domain_is_not_flagged(self):
        assert detect_display_name_impersonation("PayPal", "paypal.com") == ""
        assert detect_display_name_impersonation("Microsoft 365", "outlook.com") == ""

    def test_brand_on_unrelated_domain_is_flagged(self):
        assert detect_display_name_impersonation(
            "PayPal Service Center", "spam-sender.tk"
        ) == "paypal"

    def test_multiword_brand_is_flagged(self):
        assert detect_display_name_impersonation(
            "Wells Fargo Alerts", "wf-secure.top"
        ) == "wells fargo"

    def test_spelled_out_domain_is_flagged(self):
        assert detect_display_name_impersonation(
            "Support (paypal.com)", "evil.tk"
        ) == "paypal.com"


class TestMessageIdSubdomain:
    """R10 should tolerate the normal subdomain case."""

    SUBDOMAIN = """
Received: from mail.example.com (mail.example.com [203.0.113.5])
\tby mx.gmail.com with ESMTP id abc; Mon, 15 Jan 2024 08:30:00 -0800
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass; dmarc=pass
Date: Mon, 15 Jan 2024 08:29:45 -0800
Message-ID: <abc@mail.example.com>
Subject: Weekly report
From: Jane Doe <jane@example.com>
To: user@gmail.com
"""

    def test_message_id_subdomain_is_not_flagged(self):
        findings, _ = analyze(build(self.SUBDOMAIN))

        assert "R10" not in [f.rule_id for f in findings]

    def test_unrelated_message_id_domain_is_flagged(self):
        headers = self.SUBDOMAIN.replace("<abc@mail.example.com>", "<abc@malicious.net>")

        findings, _ = analyze(build(headers))

        assert "R10" in [f.rule_id for f in findings]
