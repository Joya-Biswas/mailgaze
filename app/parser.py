"""
Email header parser using stdlib email module and regex extraction.

This module provides functions to parse raw email headers and extract relevant
forensic information like From, To, Subject, Received chain, and auth results.
"""

import re
from datetime import datetime
from email.parser import HeaderParser
from typing import Optional

from app.body_analyzer import parse_body


def parse_headers(raw: str) -> dict:
    """
    Parse raw email headers and extract key forensic fields.

    Args:
        raw: Raw email headers as a string (headers only, no body).

    Returns:
        A dict with keys: from_, to, subject, date, message_id, reply_to,
        return_path, received_chain (list of dicts), auth_results (str).
        Missing fields are set to None or empty list/str.
    """
    try:
        # Use stdlib HeaderParser to safely parse headers
        parser = HeaderParser()
        msg = parser.parsestr(raw, headersonly=True)

        # Extract simple headers; use .get() to avoid KeyError
        result = {
            "from_": msg.get("From"),
            "to": msg.get("To"),
            "subject": msg.get("Subject"),
            "date": msg.get("Date"),
            "message_id": msg.get("Message-ID"),
            "reply_to": msg.get("Reply-To"),
            "return_path": msg.get("Return-Path"),
            "auth_results": msg.get("Authentication-Results", ""),
            # Every Authentication-Results header, topmost first. Only the
            # topmost one was added by the receiving server; the rest arrived
            # with the message and may have been written by the sender, so the
            # analyzer needs to see how many there are.
            "auth_results_all": msg.get_all("Authentication-Results") or [],
            "received_chain": [],
            # The pasted message usually carries its body too. Header rules
            # ignore it, but the link rules need it.
            "body": parse_body(raw),
        }

        # Extract all Received headers (there can be many)
        # getall() returns a list of all values for a given header
        received_lines = msg.get_all("Received") or []
        for line in received_lines:
            hop = parse_received_hop(line)
            result["received_chain"].append(hop)

        return result
    except Exception as e:
        # On any parsing error, return a minimal dict with error info
        return {
            "from_": None,
            "to": None,
            "subject": None,
            "date": None,
            "message_id": None,
            "reply_to": None,
            "return_path": None,
            "auth_results": "",
            "auth_results_all": [],
            "received_chain": [],
            "body": {"has_body": False, "links": [], "attachments": [], "text_length": 0},
            "parse_error": str(e),
        }


# The headers that actually carry forensic weight. Seeing any of these is a
# reliable sign the paste is a real header block rather than message text.
_MEANINGFUL_HEADERS = (
    "received", "from", "to", "subject", "date", "message-id",
    "return-path", "authentication-results", "delivered-to", "reply-to",
)


def looks_like_headers(raw: str) -> bool:
    """
    Decide whether a paste is an email header block at all.

    People very reasonably paste the message they can see on screen — the
    readable body — because that is what an email looks like to them. That text
    parses into an empty result, and reporting a verdict on it would be
    meaningless. This lets the caller say so instead.

    Args:
        raw: The pasted text.

    Returns:
        True if the text contains at least one recognizable header field.
    """
    if not raw or not raw.strip():
        return False

    for line in raw.splitlines():
        if not line.strip():
            break  # headers end at the first blank line

        name, separator, _ = line.partition(":")
        if separator and name.strip().lower() in _MEANINGFUL_HEADERS:
            return True

    return False


def parse_received_hop(line: str) -> dict:
    """
    Parse a single Received header line and extract IP, hostnames, and timestamp.

    Received headers are complex and vary, but generally contain:
    - from <hostname> [<ip>]
    - by <hostname>
    - with <protocol>
    - <timestamp>

    Args:
        line: A single Received header line.

    Returns:
        A dict with keys: from_host, from_ip, by_host, protocol, timestamp_str,
        timestamp (datetime or None), raw (the original line).
    """
    result = {
        "from_host": None,
        "from_ip": None,
        "by_host": None,
        "protocol": None,
        "timestamp_str": None,
        "timestamp": None,
        "raw": line,
    }

    try:
        # Extract the "from <hostname>" part
        from_match = re.search(r"from\s+([^\s\[(]+)", line, re.IGNORECASE)
        if from_match:
            result["from_host"] = from_match.group(1)

        # The sending IP is bracketed, and usually sits behind a parenthesized
        # reverse-DNS name rather than directly after the hostname:
        #     from mail.example.com (mail.example.com [203.0.113.5]) by ...
        # Only search ahead of the "by" clause so we don't pick up an address
        # belonging to the receiving host.
        from_segment = re.split(r"\sby\s", line, maxsplit=1, flags=re.IGNORECASE)[0]
        ip_match = re.search(r"\[(?:IPv6:)?([^\]]+)\]", from_segment, re.IGNORECASE)
        if ip_match and is_valid_ip(ip_match.group(1)):
            result["from_ip"] = ip_match.group(1)

        # Extract "by <hostname>" part
        by_match = re.search(r"by\s+([^\s;]+)", line, re.IGNORECASE)
        if by_match:
            result["by_host"] = by_match.group(1)

        # Extract protocol like "with SMTP" or "with ESMTP"
        proto_match = re.search(r"with\s+(\S+)", line, re.IGNORECASE)
        if proto_match:
            result["protocol"] = proto_match.group(1)

        # Extract timestamp (usually at the end after semicolon)
        # Common formats: "Mon, 1 Jan 2024 12:34:56 +0000"
        ts_match = re.search(r";\s*(.+?)$", line)
        if ts_match:
            ts_str = ts_match.group(1).strip()
            result["timestamp_str"] = ts_str
            # Try to parse the timestamp; this is lenient
            result["timestamp"] = parse_email_date(ts_str)

        return result
    except Exception:
        # If regex extraction fails, return minimal dict with raw line
        return result


def is_valid_ip(ip: str) -> bool:
    """
    Check that a string is a valid IP address (IPv4 or IPv6).

    Args:
        ip: String to check.

    Returns:
        True if the string is a valid IPv4 or IPv6 address.
    """
    import ipaddress

    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def parse_email_date(date_str: str) -> Optional[datetime]:
    """
    Attempt to parse an email date string to a datetime object.

    Email dates typically follow RFC 5322 format, e.g.:
    "Mon, 1 Jan 2024 12:34:56 +0000"

    Args:
        date_str: Email date string.

    Returns:
        A datetime object if parsing succeeds, None otherwise.
    """
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(date_str)
    except (TypeError, ValueError):
        return None
