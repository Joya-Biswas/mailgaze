"""
Unit tests for the email header parser module.

Tests cover parsing of legitimate and phishing samples, extraction of
Received chains, auth results, and graceful handling of malformed input.
"""

import pytest
from pathlib import Path
from app.parser import looks_like_headers, parse_headers, parse_received_hop


# Load sample email headers for testing
SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def load_sample(name: str) -> str:
    """Load a sample email from the samples directory."""
    sample_path = SAMPLES_DIR / f"{name}.txt"
    return sample_path.read_text(encoding="utf-8")


class TestParseHeaders:
    """Test cases for parse_headers function."""

    def test_parse_legitimate_email(self):
        """Test parsing of a legitimate email sample."""
        headers = load_sample("legitimate")
        parsed = parse_headers(headers)

        # Check that key fields are extracted
        assert parsed["from_"] is not None
        assert "sender@example.com" in parsed["from_"]
        assert parsed["subject"] is not None
        assert "Status Update" in parsed["subject"]

        # Check that authentication results were extracted
        assert parsed["auth_results"] is not None
        assert "spf" in parsed["auth_results"].lower()

        # Check that Received chain was parsed
        assert len(parsed["received_chain"]) > 0

    def test_parse_phishing_email(self):
        """Test parsing of a phishing email sample."""
        headers = load_sample("phishing")
        parsed = parse_headers(headers)

        # Check that key fields are extracted
        assert parsed["from_"] is not None
        assert "PayPal" in parsed["from_"]
        assert parsed["subject"] is not None
        assert "URGENT" in parsed["subject"]
        assert "Suspended" in parsed["subject"]

        # Check that Reply-To differs from From
        assert parsed["reply_to"] is not None
        assert parsed["reply_to"] != parsed["from_"]

        # Check that Received chain was parsed (should be long)
        assert len(parsed["received_chain"]) > 8

    def test_parse_malformed_input(self):
        """Test that malformed input is handled gracefully."""
        malformed = "This is not an email header at all. Just random text."
        parsed = parse_headers(malformed)

        # Should not raise an exception; should return a dict
        assert isinstance(parsed, dict)
        assert parsed["from_"] is None
        assert parsed["received_chain"] == []

    def test_parse_empty_input(self):
        """Test that empty input is handled gracefully."""
        parsed = parse_headers("")

        assert isinstance(parsed, dict)
        assert parsed["from_"] is None
        assert parsed["received_chain"] == []

    def test_received_chain_extraction(self):
        """Test that Received headers are properly extracted into a chain."""
        headers = load_sample("phishing")
        parsed = parse_headers(headers)

        chain = parsed["received_chain"]

        # Phishing sample should have many hops
        assert len(chain) > 5

        # Each hop should be a dict with expected keys
        for hop in chain:
            assert isinstance(hop, dict)
            assert "from_host" in hop
            assert "by_host" in hop
            assert "timestamp_str" in hop

    def test_auth_results_extraction(self):
        """Test that Authentication-Results header is extracted."""
        headers = load_sample("legitimate")
        parsed = parse_headers(headers)

        auth_results = parsed["auth_results"]

        # Should contain auth info
        assert auth_results is not None
        assert len(auth_results) > 0
        assert "spf" in auth_results.lower() or "dkim" in auth_results.lower()


class TestParseReceivedHop:
    """Test cases for parse_received_hop function."""

    def test_parse_simple_hop(self):
        """Test parsing of a simple Received header."""
        hop_line = (
            "from mail.example.com (mail.example.com [203.0.113.5]) "
            "by recipient.example.com with ESMTP id abc123; "
            "Mon, 15 Jan 2024 08:30:00 -0800"
        )

        hop = parse_received_hop(hop_line)

        assert hop["from_host"] == "mail.example.com"
        assert hop["from_ip"] == "203.0.113.5"
        assert hop["by_host"] == "recipient.example.com"
        assert hop["protocol"] == "ESMTP"
        assert hop["timestamp_str"] is not None

    def test_parse_ipv6_hop(self):
        """Test parsing of a Received header with IPv6."""
        hop_line = (
            "from mail.example.com (mail.example.com [2607:f8b0:4864:20::468]) "
            "by recipient.example.com with ESMTP id def456; "
            "Mon, 15 Jan 2024 08:30:00 -0800"
        )

        hop = parse_received_hop(hop_line)

        assert hop["from_host"] == "mail.example.com"
        assert hop["from_ip"] == "2607:f8b0:4864:20::468"
        assert hop["by_host"] == "recipient.example.com"

    def test_parse_hop_without_ip(self):
        """Test parsing of a Received header without an IP address."""
        hop_line = (
            "from mail.example.com "
            "by recipient.example.com with ESMTP id ghi789; "
            "Mon, 15 Jan 2024 08:30:00 -0800"
        )

        hop = parse_received_hop(hop_line)

        assert hop["from_host"] == "mail.example.com"
        assert hop["from_ip"] is None
        assert hop["by_host"] == "recipient.example.com"

    def test_parse_malformed_hop(self):
        """Test that malformed Received headers are handled gracefully."""
        hop_line = "This is not a valid Received header"

        hop = parse_received_hop(hop_line)

        # Should return a dict with None/default values
        assert isinstance(hop, dict)
        assert hop["from_host"] is None
        assert hop["raw"] == hop_line


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestLooksLikeHeaders:
    """
    Test cases for looks_like_headers.

    Pasting the readable message body instead of the headers is the natural
    mistake for anyone who has not seen headers before, and it used to produce
    a confident verdict about nothing.
    """

    def test_real_headers_are_recognized(self):
        assert looks_like_headers(load_sample("legitimate")) is True
        assert looks_like_headers(load_sample("phishing")) is True

    def test_a_single_header_line_is_enough(self):
        assert looks_like_headers("From: someone@example.com") is True

    def test_readable_message_body_is_rejected(self):
        body = (
            "Your resume isn't the problem\n"
            "Spam\n"
            "james...@compassfern.com\n"
            "Fri 7 Aug, 14:27 (4 days ago)\n"
            "to me\n"
            "\n"
            "Hey Joya Biswas,\n"
            "You've got the degree. Still nothing?\n"
            "Unsubscribe\n"
        )

        assert looks_like_headers(body) is False

    def test_bare_email_address_is_rejected(self):
        assert looks_like_headers("dalmanekni@tozya.com") is False

    def test_empty_input_is_rejected(self):
        assert looks_like_headers("") is False
        assert looks_like_headers("   \n  ") is False

    def test_prose_containing_a_colon_is_rejected(self):
        """A time or a sentence colon must not be mistaken for a header."""
        assert looks_like_headers("Fri 7 Aug, 14:27 (4 days ago)") is False

    def test_scanning_stops_at_the_blank_line(self):
        """A header-looking line inside the body doesn't count."""
        text = "just some text\n\nSubject: this is body content\n"

        assert looks_like_headers(text) is False
