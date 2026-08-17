"""
Live SPF and DMARC evaluation against DNS.

Every other check in Mailgaze reads the message and asks whether it is
internally consistent. That has a hard ceiling: the message is written by the
sender, so a careful forger can make it agree with itself. The checks in this
module are the first ones that consult a source the sender does not control —
the DNS records published by the domain they claim to be sending from.

The question answered here is the one that actually matters: *did the domain
this mail claims to come from authorize the machine that sent it?* An attacker
can write "spf=pass" into their own headers, but they cannot publish records in
someone else's DNS zone.

Scope and honesty about it:

- SPF evaluation implements ip4, ip6, a, mx, include, redirect, exists and all,
  with qualifiers, and honours the RFC 7208 limit of 10 DNS-querying terms.
- Macro expansion (%{s}, %{d}, ...), the deprecated ptr mechanism, and exp= are
  NOT implemented. A record using them evaluates to "permerror" rather than
  guessing, so an unsupported record can never produce a false "pass".
- DKIM is not verified here; that needs the message body and is out of scope
  for a header-only tool.

Everything degrades gracefully. If dnspython is missing, the network is
unavailable, or a lookup times out, the caller gets available=False rather than
an exception, and the analyzer simply skips the live rules.
"""

import ipaddress
import re
from typing import Optional

# RFC 7208 section 4.6.4: at most 10 mechanisms/modifiers that cause a lookup.
MAX_DNS_LOOKUPS = 10

# Kept short: these run inside a web request.
DNS_TIMEOUT_SECONDS = 3.0

# Qualifier characters to the result they produce when a mechanism matches.
_QUALIFIERS = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}

# Terms we cannot evaluate correctly. Rather than ignore them and risk calling
# an unauthorized sender "pass", a record containing one is a permerror.
_UNSUPPORTED = re.compile(r"(^|[\s])(ptr\b)|%\{", re.IGNORECASE)


class _LookupBudget:
    """Counts DNS-querying terms so a malicious record can't fan out forever."""

    def __init__(self, limit: int = MAX_DNS_LOOKUPS) -> None:
        self.remaining = limit

    def spend(self) -> bool:
        """Consume one lookup. Returns False once the budget is exhausted."""
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


def _get_resolver():
    """
    Build a resolver with short timeouts, or return None if DNS is unusable.

    Returns:
        A dns.resolver.Resolver, or None when dnspython is not installed.
    """
    try:
        import dns.resolver
    except ImportError:
        return None

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_TIMEOUT_SECONDS

    return resolver


def _query(resolver, name: str, rdtype: str) -> list:
    """
    Run one DNS query, treating "no such name" as an empty answer.

    Args:
        resolver: A dns.resolver.Resolver.
        name: The name to look up.
        rdtype: Record type, e.g. "TXT", "A", "MX".

    Returns:
        A list of rdata objects; empty if the name or record type is absent.

    Raises:
        RuntimeError: If the lookup fails for a reason that is not "absent",
            such as a timeout or a dead resolver.
    """
    import dns.resolver

    try:
        return list(resolver.resolve(name, rdtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception as exc:  # timeout, no nameservers, malformed name, ...
        raise RuntimeError(f"DNS lookup failed for {name} {rdtype}: {exc}") from exc


def _txt_strings(resolver, name: str) -> list[str]:
    """Fetch TXT records for a name, joining each record's split strings."""
    records = []
    for rdata in _query(resolver, name, "TXT"):
        parts = getattr(rdata, "strings", None)
        if parts is None:
            records.append(str(rdata).strip('"'))
        else:
            records.append(b"".join(parts).decode("utf-8", "replace"))

    return records


def find_spf_record(resolver, domain: str) -> Optional[str]:
    """
    Find the SPF record published by a domain.

    Args:
        resolver: A dns.resolver.Resolver.
        domain: The domain to look up.

    Returns:
        The SPF record text, or None if the domain publishes none.

    Raises:
        RuntimeError: If more than one SPF record exists, which RFC 7208
            requires be treated as an error rather than picking one.
    """
    spf_records = [
        txt for txt in _txt_strings(resolver, domain)
        if txt.lower().startswith("v=spf1")
    ]

    if not spf_records:
        return None
    if len(spf_records) > 1:
        raise RuntimeError(f"{domain} publishes {len(spf_records)} SPF records")

    return spf_records[0]


def _ip_in_network(ip: str, network: str, default_prefix: int) -> bool:
    """Check an IP against a CIDR block, supplying a prefix if none is given."""
    try:
        address = ipaddress.ip_address(ip)
        if "/" not in network:
            network = f"{network}/{default_prefix}"
        return address in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def _hosts_match_ip(resolver, budget: _LookupBudget, host: str, ip: str) -> bool:
    """Resolve a hostname's A/AAAA records and test them against an IP."""
    address = ipaddress.ip_address(ip)
    rdtype = "AAAA" if address.version == 6 else "A"

    for rdata in _query(resolver, host, rdtype):
        if str(rdata) == str(address):
            return True

    return False


def _evaluate_terms(resolver, domain: str, ip: str, budget: _LookupBudget) -> str:
    """
    Evaluate one domain's SPF record against a sending IP.

    Args:
        resolver: A dns.resolver.Resolver.
        domain: The domain whose SPF record to evaluate.
        ip: The sending IP address.
        budget: Shared DNS lookup budget across includes and redirects.

    Returns:
        An SPF result string: pass, fail, softfail, neutral, none, or permerror.
    """
    record = find_spf_record(resolver, domain)
    if record is None:
        return "none"

    if _UNSUPPORTED.search(record):
        # A ptr mechanism or a macro. We refuse to guess.
        return "permerror"

    redirect: Optional[str] = None

    for term in record.split()[1:]:  # skip the "v=spf1" version token
        if term.lower().startswith("redirect="):
            redirect = term.split("=", 1)[1]
            continue
        if term.lower().startswith("exp="):
            continue  # explanation string only; no bearing on the result

        qualifier = "+"
        if term[0] in _QUALIFIERS:
            qualifier, term = term[0], term[1:]

        name, _, value = term.partition(":")
        name = name.lower()
        matched = False

        if name == "all":
            matched = True

        elif name in ("ip4", "ip6"):
            matched = _ip_in_network(ip, value, 32 if name == "ip4" else 128)

        elif name == "a":
            if not budget.spend():
                return "permerror"
            target = value.split("/")[0] or domain
            matched = _hosts_match_ip(resolver, budget, target, ip)

        elif name == "mx":
            # The mx mechanism costs one lookup against the budget, not one per
            # MX host (RFC 7208 section 4.6.4). The host count is capped
            # separately at 10 by the same section.
            if not budget.spend():
                return "permerror"
            target = value.split("/")[0] or domain
            for rdata in _query(resolver, target, "MX")[:10]:
                host = str(rdata.exchange).rstrip(".")
                if _hosts_match_ip(resolver, budget, host, ip):
                    matched = True
                    break

        elif name == "include":
            if not budget.spend():
                return "permerror"
            inner = _evaluate_terms(resolver, value, ip, budget)
            if inner == "permerror":
                return "permerror"
            # An include matches only when it would itself have passed.
            matched = inner == "pass"

        elif name == "exists":
            if not budget.spend():
                return "permerror"
            matched = bool(_query(resolver, value, "A"))

        else:
            return "permerror"  # unknown mechanism

        if matched:
            return _QUALIFIERS[qualifier]

    if redirect:
        if not budget.spend():
            return "permerror"
        return _evaluate_terms(resolver, redirect, ip, budget)

    # A record with no matching term and no explicit "all" is neutral.
    return "neutral"


def evaluate_spf(domain: str, ip: str) -> dict:
    """
    Evaluate a domain's published SPF policy against the IP that sent the mail.

    Unlike reading an Authentication-Results header, this consults the domain's
    own DNS zone, which the sender of a forged message does not control.

    Args:
        domain: The domain to check, normally the Return-Path (MAIL FROM)
            domain, falling back to the From domain.
        ip: The IP address that delivered the message to the receiving server.

    Returns:
        A dict with:
          available   - False if DNS could not be consulted at all
          result      - pass | fail | softfail | neutral | none | permerror
          record      - the SPF record text, if one was found
          error       - why the check could not run, when available is False
    """
    outcome = {"available": False, "result": "unknown", "record": None, "error": ""}

    resolver = _get_resolver()
    if resolver is None:
        outcome["error"] = "dnspython is not installed"
        return outcome

    if not domain or not ip:
        outcome["error"] = "no sender domain or sending IP available"
        return outcome

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        outcome["error"] = f"sending IP {ip!r} is not a valid address"
        return outcome

    try:
        outcome["record"] = find_spf_record(resolver, domain)
        outcome["result"] = _evaluate_terms(resolver, domain, ip, _LookupBudget())
        outcome["available"] = True
    except RuntimeError as exc:
        outcome["error"] = str(exc)

    return outcome


def lookup_dmarc(domain: str) -> dict:
    """
    Fetch and parse the DMARC policy published at _dmarc.<domain>.

    Args:
        domain: The From domain.

    Returns:
        A dict with:
          available - False if DNS could not be consulted
          found     - whether a DMARC record exists
          policy    - the p= value (none, quarantine, reject) if present
          record    - the raw record text
          error     - why the check could not run
    """
    outcome = {
        "available": False,
        "found": False,
        "policy": "",
        "record": None,
        "error": "",
    }

    resolver = _get_resolver()
    if resolver is None:
        outcome["error"] = "dnspython is not installed"
        return outcome

    if not domain:
        outcome["error"] = "no sender domain available"
        return outcome

    try:
        records = [
            txt for txt in _txt_strings(resolver, f"_dmarc.{domain}")
            if txt.lower().startswith("v=dmarc1")
        ]
        outcome["available"] = True
    except RuntimeError as exc:
        outcome["error"] = str(exc)
        return outcome

    if not records:
        return outcome

    outcome["found"] = True
    outcome["record"] = records[0]

    policy = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", records[0], re.IGNORECASE)
    if policy:
        outcome["policy"] = policy.group(1).lower()

    return outcome


def run_live_checks(sender_domain: str, sending_ip: str, from_domain: str = "") -> dict:
    """
    Run both live checks, never raising.

    Args:
        sender_domain: Domain to evaluate SPF for (Return-Path, or From).
        sending_ip: The IP that delivered the message to the receiving server.
        from_domain: The From domain, used for the DMARC lookup. Defaults to
            sender_domain.

    Returns:
        A dict with "spf" and "dmarc" entries as returned by the functions
        above, plus "attempted" so the caller can tell a skipped run from a
        failed one.
    """
    try:
        return {
            "attempted": True,
            "spf": evaluate_spf(sender_domain, sending_ip),
            "dmarc": lookup_dmarc(from_domain or sender_domain),
        }
    except Exception as exc:  # belt and braces; this must never break a request
        return {
            "attempted": True,
            "spf": {"available": False, "result": "unknown", "record": None,
                    "error": str(exc)},
            "dmarc": {"available": False, "found": False, "policy": "",
                      "record": None, "error": str(exc)},
        }
