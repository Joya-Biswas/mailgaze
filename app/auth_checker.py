"""
Parse Authentication-Results headers to extract SPF, DKIM, and DMARC results.

This module parses the Authentication-Results header (RFC 7601) to extract
the results of SPF, DKIM, and DMARC checks already performed by the receiving
mail server. It does NOT perform the cryptographic verification itself.

Because of that, *which* Authentication-Results header you read matters more
than what it says. A sender controls every header in the message they send, so
anyone can write "spf=pass" into their own mail. Only the header added by the
mail server that received the message means anything, and that server stamps
its own name (the authserv-id) at the front of the header it writes.

evaluate_auth() is therefore the function to use: it reads only the topmost
header and reports whether that header's authserv-id actually belongs to the
receiving server. read_auth_results() parses a single header value in
isolation and cannot tell you anything about trust.
"""

import re


def _read_method(auth_results_str: str, method: str) -> dict:
    """
    Extract one authentication method's result and its trailing detail.

    RFC 7601 permits a parenthesized comment and further property/value pairs
    after the result token, e.g.

        spf=pass (google.com: domain of x@y.com designates 1.2.3.4 ...) smtp.mailfrom=x@y.com

    so the result must not be anchored to a following ";" — real headers rarely
    put one there.

    Args:
        auth_results_str: The full Authentication-Results header value.
        method: The method name to look for ("spf", "dkim", or "dmarc").

    Returns:
        A dict with "result" and "detail" keys.
    """
    # The negative lookbehind keeps "dkim=" from matching inside "dkim-adsp=".
    match = re.search(
        r"(?<![\w.-])" + method + r"\s*=\s*(\w+)",
        auth_results_str,
        re.IGNORECASE,
    )
    if not match:
        return {"result": "missing", "detail": ""}

    # Detail is whatever follows on the same clause: stop at the ";" that ends
    # this method's entry, or at the line break if it has no ";".
    detail = auth_results_str[match.end():].split(";")[0].split("\n")[0].strip()

    return {"result": match.group(1).lower(), "detail": detail}


def read_auth_results(auth_results_str: str) -> dict:
    """
    Parse an Authentication-Results header and extract SPF, DKIM, DMARC info.

    Example header:
    Authentication-Results: mx.example.com;
      spf=pass smtp.mailfrom=user@example.com;
      dkim=pass header.d=example.com;
      dmarc=pass (p=reject fo=1:d:s)

    Args:
        auth_results_str: The value of the Authentication-Results header,
                         or an empty string if the header is missing.

    Returns:
        A dict with keys "spf", "dkim", "dmarc", each containing:
        {"result": "<pass|fail|neutral|softfail|missing>", "detail": "<optional info>"}
    """
    result = {
        "spf": {"result": "missing", "detail": ""},
        "dkim": {"result": "missing", "detail": ""},
        "dmarc": {"result": "missing", "detail": ""},
    }

    if not auth_results_str or not auth_results_str.strip():
        return result

    try:
        for method in ("spf", "dkim", "dmarc"):
            result[method] = _read_method(auth_results_str, method)

        return result
    except Exception:
        # On any parse error, return the "missing" defaults
        return result


def registrable_domain(host: str) -> str:
    """
    Reduce a hostname to the last two labels, as a cheap stand-in for the
    registrable domain.

    "mx.google.com" -> "google.com", "example.com" -> "example.com"

    This is deliberately simple. It over-reduces multi-part public suffixes
    such as "co.uk", which makes it slightly *more* willing to call two hosts
    related. Trust decisions below use it only to compare a receiving server
    against the name it stamped on its own header, where both sides come from
    the same infrastructure, so the imprecision is acceptable.

    Args:
        host: A hostname, possibly fully qualified.

    Returns:
        The last two labels, lowercased, or the input if it has fewer.
    """
    if not host:
        return ""

    labels = host.strip().lower().rstrip(".").split(".")
    if len(labels) < 2:
        return labels[0] if labels else ""

    return ".".join(labels[-2:])


def _authserv_id(auth_results_str: str) -> str:
    """
    Extract the authserv-id: the name the receiving server stamps on the header.

    RFC 7601 puts it first, before the first ";", optionally followed by a
    version number.

    Args:
        auth_results_str: A single Authentication-Results header value.

    Returns:
        The authserv-id, or "" if the header is empty.
    """
    head = auth_results_str.split(";")[0].strip()
    # Strip an optional trailing version number ("mx.example.com 1").
    head = re.sub(r"\s+\d+$", "", head)

    return head.strip().lower()


def evaluate_auth(auth_headers: list[str], receiving_host: str | None) -> dict:
    """
    Read authentication results, but only from a header we have reason to trust.

    The topmost Authentication-Results header is the one the final receiving
    server added; anything below it was already in the message when that server
    saw it, and so could have been written by the sender. We read the topmost
    header only, and we trust it only if its authserv-id belongs to the same
    domain as the server that received the message.

    Args:
        auth_headers: Every Authentication-Results value, topmost first.
        receiving_host: The "by" host of the topmost Received hop, i.e. the
            server that accepted the message last.

    Returns:
        A dict with "spf", "dkim" and "dmarc" entries as read_auth_results
        returns, plus:
          trusted        - whether the header we read came from the receiver
          authserv       - the authserv-id we read it from
          reason         - why the header was or wasn't trusted
          extra_headers  - count of further Authentication-Results below the top
    """
    base = {
        "spf": {"result": "missing", "detail": ""},
        "dkim": {"result": "missing", "detail": ""},
        "dmarc": {"result": "missing", "detail": ""},
        "trusted": False,
        "authserv": "",
        "reason": "",
        "extra_headers": 0,
    }

    headers = [h for h in (auth_headers or []) if h and h.strip()]
    if not headers:
        base["reason"] = "no Authentication-Results header present"
        return base

    top = headers[0]
    base.update(read_auth_results(top))
    base["authserv"] = _authserv_id(top)
    base["extra_headers"] = len(headers) - 1

    if not receiving_host:
        base["reason"] = (
            "no Received chain to identify the receiving server, so the "
            "header's origin cannot be confirmed"
        )
        return base

    if not base["authserv"]:
        base["reason"] = "header does not name the server that produced it"
        return base

    if registrable_domain(base["authserv"]) == registrable_domain(receiving_host):
        base["trusted"] = True
        base["reason"] = f"stamped by the receiving server ({base['authserv']})"
    else:
        base["reason"] = (
            f"stamped by {base['authserv']}, which is not the receiving server "
            f"({receiving_host}) — the sender may have written this header"
        )

    return base
