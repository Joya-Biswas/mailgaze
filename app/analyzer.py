"""
Email forensics analysis: apply detection rules and determine verdict.

This module implements a rule-based analyzer that examines parsed email headers
and produces a list of findings (rules that triggered) and an overall verdict
(Likely Phishing, Suspicious, or Likely Legitimate).
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
import ipaddress
import re

from app.auth_checker import evaluate_auth, registrable_domain
from app.geo import lookup_ip


@dataclass
class Finding:
    """
    Represents a single forensic finding triggered by a rule.

    `evidence` carries the concrete values the finding rests on, so the report
    can show its working rather than asking to be believed. A reader who is
    told "a link goes somewhere other than it claims" has no reason to accept
    it; one who is shown "paypal.com -> evil-login.tk" can see it for
    themselves. Two shapes are supported:

        {"left_label": ..., "left": ..., "right_label": ..., "right": ...}
        {"fact_label": ..., "fact": ...}
    """
    rule_id: str  # e.g., "R1", "R2"
    severity: Literal["low", "medium", "high"]
    title: str
    description: str
    evidence: dict | None = None


def analyze(parsed: dict, live_checks: bool = False) -> tuple[list[Finding], str]:
    """
    Run forensic rules on parsed email headers and produce findings + verdict.

    Args:
        parsed: A dict (output of parser.parse_headers).
        live_checks: If True, additionally evaluate the sender domain's
            published SPF and DMARC records via DNS (rules R13-R15). This is
            the only part of the analysis that consults a source outside the
            message, so it is the only part a forger cannot control — but it
            sends DNS queries for the sender's domain, so it is opt-in.

    Returns:
        A tuple (findings, verdict) where:
        - findings: list of Finding objects, sorted by severity (high first)
        - verdict: str in {"Likely Phishing", "Suspicious", "Likely Legitimate"}
    """
    findings: list[Finding] = []

    # Read the authentication results, but only from a header we can attribute
    # to the receiving server. The "by" host of the topmost Received hop is the
    # server that accepted the message last.
    received_chain = parsed.get("received_chain", [])
    receiving_host = received_chain[0].get("by_host") if received_chain else None

    auth_headers = parsed.get("auth_results_all")
    if auth_headers is None:
        # Older callers only pass the single value.
        single = parsed.get("auth_results", "")
        auth_headers = [single] if single else []

    auth_results = evaluate_auth(auth_headers, receiving_host)

    # ===== Rule R1: SPF, DKIM, or DMARC missing or failed =====
    # An untrusted header proves nothing, so its "pass" values are not treated
    # as passing here. R11 reports the untrustworthiness separately.
    if not auth_results["trusted"]:
        auth_is_failing = True
    else:
        auth_is_failing = (
            auth_results["spf"]["result"] in ("missing", "fail", "softfail") or
            auth_results["dkim"]["result"] in ("missing", "fail") or
            auth_results["dmarc"]["result"] in ("missing", "fail")
        )

    if auth_is_failing:
        findings.append(Finding(
            rule_id="R1",
            severity="high",
            title="Authentication checks failed or missing",
            description="SPF, DKIM, or DMARC is not passing. The email lacks proper authentication.",
        ))

    # ===== Rule R11: authentication claim cannot be attributed to the receiver =====
    # Any sender can write "spf=pass" into their own headers. A result only
    # means something if the server that received the message is the one that
    # wrote it down.
    if auth_headers and not auth_results["trusted"]:
        findings.append(Finding(
            rule_id="R11",
            severity="high",
            title="Unverifiable authentication claim",
            description=(
                "The email carries an Authentication-Results header, but it "
                f"cannot be attributed to the receiving server: {auth_results['reason']}. "
                "Treat the SPF/DKIM/DMARC results shown as claims made by the "
                "sender, not as verified facts."
            ),
            evidence={
                "left_label": "The email says it was checked by",
                "left": auth_results["authserv"] or "(unnamed)",
                "right_label": "But the server that received it was",
                "right": receiving_host or "(no record)",
            },
        ))

    # ===== Rule R12: more than one Authentication-Results header =====
    if auth_results["extra_headers"] > 0:
        findings.append(Finding(
            rule_id="R12",
            severity="medium",
            title="Multiple authentication headers",
            description=(
                f"The message carries {auth_results['extra_headers'] + 1} "
                "Authentication-Results headers. Only the topmost was added by "
                "the receiving server; the others arrived with the message and "
                "may have been inserted by the sender to look authentic."
            ),
        ))

    # ===== Rule R2: From display name != From email domain =====
    from_addr = parsed.get("from_")
    if from_addr:
        display_name, email_part = extract_display_and_email(from_addr)
        email_domain = extract_domain(email_part)
        if display_name and email_domain:
            # Only report a display name that claims an identity the sending
            # domain doesn't back — not every name that differs from the domain.
            claimed = detect_display_name_impersonation(display_name, email_domain)
            if claimed:
                findings.append(Finding(
                    rule_id="R2",
                    severity="medium",
                    title="Display name impersonates another sender",
                    description=f'From header presents itself as "{display_name}", which claims '
                                f"{claimed}, but the message was sent from {email_domain}.",
                    evidence={
                        "left_label": "The name it shows you",
                        "left": display_name,
                        "right_label": "The address it came from",
                        "right": email_domain,
                    },
                ))

    # ===== Rule R3: Reply-To uses free email when From is a non-free domain =====
    reply_to = parsed.get("reply_to")
    if reply_to and from_addr:
        reply_domain = extract_domain(reply_to)
        from_domain = extract_domain(from_addr)
        free_domains = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"}
        if (reply_domain in free_domains and from_domain and
            from_domain not in free_domains and from_domain != reply_domain):
            findings.append(Finding(
                rule_id="R3",
                severity="high",
                title="Reply-To uses free email; From is corporate",
                description=f"Reply-To is at {reply_domain} but From is at {from_domain}. "
                            f"Suspicious mismatch.",
                evidence={
                    "left_label": "Appears to be from",
                    "left": from_domain,
                    "right_label": "But replies would go to",
                    "right": reply_domain,
                },
            ))

    # ===== Rule R4: Return-Path domain != From domain =====
    return_path = parsed.get("return_path")
    if return_path and from_addr:
        return_domain = extract_domain(return_path)
        from_domain = extract_domain(from_addr)
        if return_domain and from_domain and return_domain != from_domain:
            findings.append(Finding(
                rule_id="R4",
                severity="medium",
                title="Return-Path domain mismatch",
                description=f"Return-Path ({return_domain}) differs from From domain ({from_domain}).",
                evidence={
                    "left_label": "Shown as from",
                    "left": from_domain,
                    "right_label": "Actually sent by",
                    "right": return_domain,
                },
            ))

    # ===== Rule R5: Received chain has impossible geographic jump =====
    if len(received_chain) >= 2:
        for i in range(1, len(received_chain)):
            prev_hop = received_chain[i - 1]
            curr_hop = received_chain[i]

            prev_ip = prev_hop.get("from_ip")
            curr_ip = curr_hop.get("from_ip")
            prev_ts = prev_hop.get("timestamp")
            curr_ts = curr_hop.get("timestamp")

            if prev_ip and curr_ip and prev_ts and curr_ts:
                prev_geo = lookup_ip(prev_ip)
                curr_geo = lookup_ip(curr_ip)

                # Check if both locations are known
                if prev_geo["lat"] is not None and curr_geo["lat"] is not None:
                    distance_km = haversine_distance(
                        prev_geo["lat"], prev_geo["lon"],
                        curr_geo["lat"], curr_geo["lon"]
                    )
                    time_delta_sec = (curr_ts - prev_ts).total_seconds()

                    # If distance > 5000 km and time < 60 sec, it's impossible
                    if distance_km > 5000 and 0 < time_delta_sec < 60:
                        findings.append(Finding(
                            rule_id="R5",
                            severity="high",
                            title="Impossible geographic jump detected",
                            description=f"Email traveled {distance_km:.0f} km in {time_delta_sec:.0f} seconds. "
                                         f"From {prev_geo['city']}, {prev_geo['country']} to "
                                         f"{curr_geo['city']}, {curr_geo['country']}.",
                        ))
                        break  # Report only the first impossible jump

    # ===== Rule R6: Received chain has more than 8 hops =====
    if len(received_chain) > 8:
        findings.append(Finding(
            rule_id="R6",
            severity="low",
            title="Long Received chain",
            description=f"Email has {len(received_chain)} hops. Unusual but not necessarily malicious.",
        ))

    # ===== Rule R7: Hop-to-hop time delta > 1 hour =====
    if len(received_chain) >= 2:
        for i in range(1, len(received_chain)):
            prev_ts = received_chain[i - 1].get("timestamp")
            curr_ts = received_chain[i].get("timestamp")
            if prev_ts and curr_ts:
                delta = prev_ts - curr_ts
                if delta > timedelta(hours=1):
                    findings.append(Finding(
                        rule_id="R7",
                        severity="medium",
                        title="Long delay between hops",
                        description=f"Email delayed {delta.total_seconds() / 3600:.1f} hours between hops. "
                                     f"Could indicate mail system issues or spoofing.",
                    ))
                    break  # Report only the first long delay

    # ===== Rule R8: Subject contains phishing keywords =====
    subject = parsed.get("subject", "")
    phishing_keywords = {
        "urgent", "verify", "suspended", "locked", "action required",
        "confirm your account", "click here", "update payment", "unusual activity",
        "confirm identity", "re-activate", "reset password"
    }
    if subject:
        subject_lower = subject.lower()
        found_keywords = [kw for kw in phishing_keywords if kw in subject_lower]
        if found_keywords:
            findings.append(Finding(
                rule_id="R8",
                severity="low",
                title="Suspicious subject line",
                description=f"Subject contains phishing keywords: {', '.join(found_keywords)}.",
            ))

    # ===== Rule R9: Date header > 24 hours different from earliest Received timestamp =====
    date_str = parsed.get("date")
    if date_str and received_chain:
        from app.parser import parse_email_date
        date_dt = parse_email_date(date_str)

        # Find the earliest (first) Received timestamp
        first_received = None
        for hop in reversed(received_chain):
            if hop.get("timestamp"):
                first_received = hop.get("timestamp")
                break

        if date_dt and first_received:
            delta = abs((date_dt - first_received).total_seconds())
            if delta > 86400:  # 24 hours in seconds
                findings.append(Finding(
                    rule_id="R9",
                    severity="medium",
                    title="Date header anomaly",
                    description=f"Date header is {delta / 3600:.1f} hours different from earliest Received timestamp.",
                ))

    # ===== Rule R10: Message-ID domain != From domain =====
    message_id = parsed.get("message_id")
    if message_id and from_addr:
        # Extract domain from Message-ID (usually has format <id@domain>)
        mid_domain_match = re.search(r"@([^\>]+)", message_id)
        mid_domain = mid_domain_match.group(1) if mid_domain_match else None
        from_domain = extract_domain(from_addr)

        # Mail systems routinely stamp the Message-ID with a subdomain of the
        # sending domain (mail.example.com for mail from example.com), so
        # compare registrable domains rather than exact hostnames.
        if (mid_domain and from_domain and
                registrable_domain(mid_domain) != registrable_domain(from_domain)):
            findings.append(Finding(
                rule_id="R10",
                severity="low",
                title="Message-ID domain mismatch",
                description=f"Message-ID domain ({mid_domain}) differs from From domain ({from_domain}).",
                evidence={
                    "left_label": "Sender domain",
                    "left": from_domain,
                    "right_label": "ID stamped by",
                    "right": mid_domain,
                },
            ))

    # ===== Rules R13-R16: live SPF and DMARC evaluation (opt-in) =====
    # Everything above reads the message and checks it against itself, which a
    # careful forger can satisfy. These rules ask the sender's own DNS instead.
    if live_checks:
        findings.extend(
            _live_dns_findings(parsed, from_addr, auth_results["spf"]["result"])
        )

    # ===== Rules R17-R20: what the message asks you to click =====
    findings.extend(_link_findings(parsed, from_addr))

    # ===== Compute verdict based on findings =====
    high_count = sum(1 for f in findings if f.severity == "high")
    medium_count = sum(1 for f in findings if f.severity == "medium")

    if high_count >= 2 or (high_count == 1 and medium_count >= 2):
        verdict = "Likely Phishing"
    elif high_count == 1 or medium_count >= 3:
        verdict = "Suspicious"
    else:
        verdict = "Likely Legitimate"

    # Sort findings by severity (high first)
    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: severity_order[f.severity])

    return findings, verdict


def _link_findings(parsed: dict, from_addr: str | None) -> list[Finding]:
    """
    Inspect the links in the message body.

    Header rules establish who sent a message. These ask what it wants you to
    do, which for phishing is almost always "click this". A link whose visible
    text names one destination while pointing at another is the most reliable
    single indicator in the field, and it is invisible to header analysis.

    Args:
        parsed: The parsed message, including the decoded body.
        from_addr: The raw From header value.

    Returns:
        A list of Findings; empty when the paste carried no body.
    """
    from app.body_analyzer import URL_SHORTENERS, is_deceptive

    body = parsed.get("body") or {}
    links = body.get("links") or []
    if not links:
        return []

    findings: list[Finding] = []
    sender_domain = registrable_domain(extract_domain(from_addr)) if from_addr else ""

    deceptive = [link for link in links if is_deceptive(link)]
    if deceptive:
        example = deceptive[0]
        findings.append(Finding(
            rule_id="R17",
            severity="high",
            title="A link goes somewhere other than it claims",
            description=(
                f'A link reading "{example["display"][:60]}" actually points to '
                f'{example["host"]}. Text that names one destination while the link '
                f"leads to another is the most common trick in phishing email"
                + (f" ({len(deceptive)} such links found)." if len(deceptive) > 1 else ".")
            ),
            evidence={
                "left_label": "The link shows you",
                "left": example["display"][:60] or example["display_domain"],
                "right_label": "But it actually opens",
                "right": example["host"],
            },
        ))

    punycode = [link for link in links if "xn--" in link["host"]]
    if punycode:
        findings.append(Finding(
            rule_id="R18",
            severity="high",
            title="A link uses a disguised (lookalike) domain",
            description=(
                f"{punycode[0]['host']} is written in punycode, which lets a domain "
                f"display as familiar letters while actually being different "
                f"characters. This is used to imitate well-known websites."
            ),
            evidence={
                "fact_label": "The disguised address",
                "fact": punycode[0]["host"],
            },
        ))

    raw_ip_links = []
    for link in links:
        try:
            ipaddress.ip_address(link["host"])
            raw_ip_links.append(link)
        except ValueError:
            continue

    if raw_ip_links:
        findings.append(Finding(
            rule_id="R19",
            severity="medium",
            title="A link points to a bare IP address",
            description=(
                f"A link goes directly to {raw_ip_links[0]['host']} instead of a "
                f"domain name. Legitimate organisations use named websites."
            ),
            evidence={
                "fact_label": "The link opens",
                "fact": raw_ip_links[0]["href"][:80],
            },
        ))

    shortened = [
        link for link in links
        if registrable_domain(link["host"]) in URL_SHORTENERS
    ]
    if shortened:
        findings.append(Finding(
            rule_id="R20",
            severity="low",
            title="A link is hidden behind a shortener",
            description=(
                f"A link uses {shortened[0]['host']}, which conceals the real "
                f"destination until you click it."
            ),
            evidence={
                "fact_label": "The hidden link",
                "fact": shortened[0]["href"][:80],
            },
        ))

    return findings


# Domains and TLDs RFC 2606 reserves for documentation and testing. Real mail
# never comes from these, and they publish deliberately restrictive SPF.
_RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}
_RESERVED_TLDS = {"test", "example", "invalid", "localhost"}


def is_reserved_domain(domain: str) -> bool:
    """
    Check whether a domain is reserved for documentation or testing (RFC 2606).

    Args:
        domain: The domain to check.

    Returns:
        True if the domain can never carry real mail.
    """
    if not domain:
        return False

    domain = domain.strip().lower().rstrip(".")

    return (
        registrable_domain(domain) in _RESERVED_DOMAINS
        or domain.rsplit(".", 1)[-1] in _RESERVED_TLDS
    )


def _live_dns_findings(
    parsed: dict, from_addr: str | None, claimed_spf: str = "missing"
) -> list[Finding]:
    """
    Evaluate the sender domain's published SPF and DMARC records.

    SPF is checked against the IP that delivered the message to the receiving
    server — the "from" IP of the topmost Received hop. SPF authorizes the
    envelope sender, so the domain checked is the Return-Path domain where one
    is present, falling back to the From domain.

    Args:
        parsed: The parsed headers.
        from_addr: The raw From header value.
        claimed_spf: The SPF result the message's own headers assert, used to
            detect a claim that DNS contradicts.

    Returns:
        A list of Findings. Empty if the lookups could not be performed, since
        an unreachable resolver is not evidence about the message.
    """
    from app.dns_checks import run_live_checks

    received_chain = parsed.get("received_chain", [])
    sending_ip = received_chain[0].get("from_ip") if received_chain else None

    from_domain = extract_domain(from_addr) if from_addr else ""
    return_path = parsed.get("return_path")
    envelope_domain = extract_domain(return_path) if return_path else ""
    spf_domain = envelope_domain or from_domain

    if not spf_domain or not sending_ip:
        return []

    # SPF authorizes public senders. A private, reserved or documentation
    # address (RFC 1918, RFC 5737, RFC 3849) can never legitimately appear in
    # anyone's SPF record, so evaluating one produces a guaranteed failure that
    # says nothing about the message.
    try:
        if not ipaddress.ip_address(sending_ip).is_global:
            return []
    except ValueError:
        return []

    # Likewise for the reserved documentation domains of RFC 2606. They publish
    # "v=spf1 -all" precisely so nothing can send as them, so any synthetic
    # example built on one fails by construction. The bundled samples use these,
    # and reporting a fabricated demo as forged would be noise, not a finding.
    if is_reserved_domain(spf_domain) or is_reserved_domain(from_domain):
        return []

    results = run_live_checks(spf_domain, sending_ip, from_domain)
    findings: list[Finding] = []

    spf = results["spf"]

    # ===== Rule R16: the message's claim contradicts the domain's own DNS =====
    # This is the strongest signal the tool has. A forger writes "spf=pass"
    # into their headers, but the domain's published record is beyond their
    # reach, so the two disagree. A genuine message evaluates to pass and no
    # contradiction exists.
    #
    # Legitimate forwarding does not trigger this: a forwarder's IP fails SPF,
    # but then the receiving server records that failure too, so the claim and
    # the evaluation agree. Only a fabricated pass produces a mismatch.
    if spf["available"] and claimed_spf == "pass" and spf["result"] in ("fail", "softfail", "none"):
        detail = {
            "fail": "explicitly does not authorize",
            "softfail": "does not list",
            "none": "publishes no SPF record covering",
        }[spf["result"]]
        findings.append(Finding(
            rule_id="R16",
            severity="high",
            title="Authentication claim contradicted by the sender's own DNS",
            description=(
                f"The message asserts that SPF passed, but {spf_domain} {detail} "
                f"{sending_ip}. The claim comes from the message itself, which a "
                f"sender controls; the SPF record comes from the domain's DNS, "
                f"which they do not. A genuine message from this domain would pass."
            ),
            evidence={
                "left_label": "The email claims",
                "left": "SPF passed",
                "right_label": f"But {spf_domain}'s own DNS says",
                "right": f"{sending_ip} is not authorized",
            },
        ))

    if spf["available"]:
        # Only an explicit rejection is treated as evidence. neutral, permerror
        # and temperror all mean "cannot conclude", and must not be scored.
        if spf["result"] == "fail":
            findings.append(Finding(
                rule_id="R13",
                severity="high",
                title="Sending server is not authorized by the domain (live SPF)",
                description=(
                    f"{spf_domain} publishes an SPF record, and that record does not "
                    f"authorize {sending_ip} to send its mail. This was checked "
                    f"against DNS directly, so it does not rely on anything the "
                    f"message claims about itself."
                ),
            ))
        elif spf["result"] == "softfail":
            findings.append(Finding(
                rule_id="R13",
                severity="medium",
                title="Sending server is not a listed sender (live SPF softfail)",
                description=(
                    f"{spf_domain}'s SPF record does not list {sending_ip}, but marks "
                    f"unlisted senders as a soft failure rather than a hard one."
                ),
            ))
        elif spf["result"] == "none":
            findings.append(Finding(
                rule_id="R14",
                severity="medium",
                title="Sender domain publishes no SPF record",
                description=(
                    f"{spf_domain} publishes no SPF record, so there is no way to tell "
                    f"which servers may legitimately send its mail. Anyone can send "
                    f"mail claiming to be from this domain."
                ),
            ))

    dmarc = results["dmarc"]
    if dmarc["available"] and from_domain:
        if not dmarc["found"]:
            findings.append(Finding(
                rule_id="R15",
                severity="low",
                title="Sender domain publishes no DMARC policy",
                description=(
                    f"{from_domain} has no DMARC record, so it gives receiving servers "
                    f"no instruction about what to do with mail that fails "
                    f"authentication."
                ),
            ))
        elif dmarc["policy"] == "none":
            findings.append(Finding(
                rule_id="R15",
                severity="low",
                title="Sender domain's DMARC policy takes no action",
                description=(
                    f"{from_domain} publishes DMARC with p=none, which asks receivers "
                    f"to monitor but not to reject or quarantine failing mail."
                ),
            ))

    return findings


def extract_display_and_email(from_header: str) -> tuple[str, str]:
    """
    Split a From header into display name and email address.

    Examples:
      "John Doe <john@example.com>" -> ("John Doe", "john@example.com")
      "john@example.com" -> ("", "john@example.com")

    Args:
        from_header: The From header value.

    Returns:
        A tuple (display_name, email_address). Either may be empty string.
    """
    # Match pattern: "Display Name <email@domain>"
    match = re.match(r'^(.+?)\s*<(.+?)>$', from_header.strip())
    if match:
        # RFC 5322 quotes a display name containing spaces or punctuation;
        # the quotes are syntax, not part of the name.
        display = match.group(1).strip().strip('"').strip()
        return display, match.group(2).strip()

    # No angle brackets; assume the whole thing is an email
    return "", from_header.strip()


def extract_domain(email_or_addr: str) -> str:
    """
    Extract the domain part from an email address or address with display name.

    Args:
        email_or_addr: Email address, possibly with display name.

    Returns:
        The domain part (e.g., "example.com"), or empty string if not found.
    """
    # Remove angle brackets if present
    cleaned = email_or_addr.replace("<", "").replace(">", "").strip()

    # Extract domain after @
    match = re.search(r'@(.+?)(?:\s|$)', cleaned)
    if match:
        return match.group(1).lower()

    return ""


# Brands that phishing commonly impersonates, mapped to the domains that
# legitimately send their mail. Only names distinctive enough that seeing one
# in a display name is a deliberate claim of identity, not a coincidence.
IMPERSONATED_BRANDS = {
    "paypal": {"paypal.com", "paypal.co.uk"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com", "office365.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazonses.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "mail.instagram.com"},
    "linkedin": {"linkedin.com"},
    "whatsapp": {"whatsapp.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com", "usps.gov"},
    "chase": {"chase.com"},
    "wells fargo": {"wellsfargo.com"},
    "bank of america": {"bankofamerica.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    "barclays": {"barclays.co.uk", "barclays.com"},
}

# A bare domain sitting inside a display name, e.g. "Support (paypal.com)".
_DOMAIN_IN_TEXT = re.compile(r"\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)


def detect_display_name_impersonation(display_name: str, email_domain: str) -> str:
    """
    Detect a display name that claims an identity the sending domain doesn't back.

    This looks for a *claim of identity*, not merely a difference. A display
    name of "John Smith" on mail from example.com is completely ordinary and is
    not reported — a human name is not a claim about a domain. What is reported
    is a display name that names a brand, or spells out a domain, that the
    actual sending domain does not match.

    Args:
        display_name: The display name part of the From header.
        email_domain: The domain of the actual From address.

    Returns:
        A short description of the identity being claimed, or "" if the display
        name makes no claim that conflicts with the sending domain.
    """
    if not display_name or not email_domain:
        return ""

    display_lower = display_name.lower()
    sender = registrable_domain(email_domain)

    # A display name that spells out a domain is claiming to be that domain.
    for candidate in _DOMAIN_IN_TEXT.findall(display_lower):
        # Require a plausible TLD so "v2.1" or "Inc." don't count.
        if len(candidate.rsplit(".", 1)[-1]) < 2:
            continue
        if registrable_domain(candidate) != sender:
            return candidate
        return ""

    # A display name that names a brand is claiming to be that brand. Brand
    # words may be run together or separated ("WellsFargo", "Wells Fargo"), so
    # allow optional separators between them, but keep the outer word
    # boundaries so "chase" doesn't match inside "purchase".
    for brand, legitimate in IMPERSONATED_BRANDS.items():
        pattern = r"\s*".join(re.escape(word) for word in brand.split())
        if not re.search(rf"\b{pattern}\b", display_lower):
            continue
        if sender in {registrable_domain(d) for d in legitimate}:
            return ""
        return brand

    return ""


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great-circle distance between two points on Earth (in kilometers).

    Args:
        lat1, lon1: Latitude and longitude of first point (in degrees).
        lat2, lon2: Latitude and longitude of second point (in degrees).

    Returns:
        Distance in kilometers.
    """
    import math

    # Earth's mean radius in kilometers
    earth_radius_km = 6371

    # Convert degrees to radians
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    # Haversine formula
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))

    return earth_radius_km * c
