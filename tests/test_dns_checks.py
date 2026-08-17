"""
Tests for live SPF/DMARC evaluation.

DNS is faked throughout: a test suite that depends on the network is slow,
flaky, and quietly wrong the day a real record changes. The fake resolver
serves a small hand-written zone and raises the same exceptions dnspython does.
"""

import dns.resolver
import pytest

from app import dns_checks
from app.analyzer import analyze, is_reserved_domain
from app.dns_checks import (
    evaluate_spf,
    lookup_dmarc,
    run_live_checks,
)
from app.parser import parse_headers


class FakeTXT:
    """Stands in for a TXT rdata object."""

    def __init__(self, text: str) -> None:
        self.strings = [text.encode()]


class FakeMX:
    """Stands in for an MX rdata object."""

    def __init__(self, host: str) -> None:
        self.exchange = host


class FakeAddress:
    """Stands in for an A/AAAA rdata object."""

    def __init__(self, ip: str) -> None:
        self.ip = ip

    def __str__(self) -> str:
        return self.ip


class FakeResolver:
    """Serves a canned zone; anything absent raises NXDOMAIN like dnspython."""

    timeout = 1
    lifetime = 1

    def __init__(self, zone: dict) -> None:
        self.zone = zone
        self.queries = []

    def resolve(self, name, rdtype):
        key = (str(name).lower().rstrip("."), rdtype.upper())
        self.queries.append(key)
        if key in self.zone:
            return self.zone[key]
        raise dns.resolver.NXDOMAIN(f"no such name: {key}")


@pytest.fixture
def zone(monkeypatch):
    """Install a fake resolver and hand the test its mutable zone."""
    records: dict = {}
    monkeypatch.setattr(dns_checks, "_get_resolver", lambda: FakeResolver(records))
    return records


def spf(zone_dict, domain, record):
    zone_dict[(domain, "TXT")] = [FakeTXT(record)]


class TestEvaluateSpf:
    """Test cases for evaluate_spf."""

    def test_ip4_match_passes(self, zone):
        spf(zone, "example.org", "v=spf1 ip4:192.0.2.0/24 -all")

        assert evaluate_spf("example.org", "192.0.2.7")["result"] == "pass"

    def test_unlisted_ip_hard_fails(self, zone):
        spf(zone, "example.org", "v=spf1 ip4:192.0.2.0/24 -all")

        assert evaluate_spf("example.org", "198.51.100.9")["result"] == "fail"

    def test_unlisted_ip_soft_fails(self, zone):
        spf(zone, "example.org", "v=spf1 ip4:192.0.2.0/24 ~all")

        assert evaluate_spf("example.org", "198.51.100.9")["result"] == "softfail"

    def test_no_record_is_none(self, zone):
        result = evaluate_spf("example.org", "198.51.100.9")

        assert result["available"] is True
        assert result["result"] == "none"

    def test_ip6_match_passes(self, zone):
        spf(zone, "example.org", "v=spf1 ip6:2001:db8::/32 -all")

        assert evaluate_spf("example.org", "2001:db8::1")["result"] == "pass"

    def test_include_delegates(self, zone):
        spf(zone, "example.org", "v=spf1 include:sender.test -all")
        spf(zone, "sender.test", "v=spf1 ip4:203.0.113.0/24 -all")

        assert evaluate_spf("example.org", "203.0.113.9")["result"] == "pass"
        assert evaluate_spf("example.org", "198.51.100.9")["result"] == "fail"

    def test_redirect_delegates(self, zone):
        spf(zone, "example.org", "v=spf1 redirect=policy.test")
        spf(zone, "policy.test", "v=spf1 ip4:203.0.113.0/24 -all")

        assert evaluate_spf("example.org", "203.0.113.9")["result"] == "pass"
        assert evaluate_spf("example.org", "198.51.100.9")["result"] == "fail"

    def test_a_mechanism(self, zone):
        spf(zone, "example.org", "v=spf1 a -all")
        zone[("example.org", "A")] = [FakeAddress("192.0.2.5")]

        assert evaluate_spf("example.org", "192.0.2.5")["result"] == "pass"
        assert evaluate_spf("example.org", "192.0.2.6")["result"] == "fail"

    def test_mx_mechanism(self, zone):
        spf(zone, "example.org", "v=spf1 mx -all")
        zone[("example.org", "MX")] = [FakeMX("mail.example.org")]
        zone[("mail.example.org", "A")] = [FakeAddress("192.0.2.5")]

        assert evaluate_spf("example.org", "192.0.2.5")["result"] == "pass"

    def test_ptr_mechanism_is_permerror_not_a_guess(self, zone):
        """Unsupported terms must never resolve to a pass."""
        spf(zone, "example.org", "v=spf1 ptr -all")

        assert evaluate_spf("example.org", "192.0.2.5")["result"] == "permerror"

    def test_macros_are_permerror(self, zone):
        spf(zone, "example.org", "v=spf1 exists:%{i}.spf.example.org -all")

        assert evaluate_spf("example.org", "192.0.2.5")["result"] == "permerror"

    def test_lookup_budget_stops_runaway_records(self, zone):
        """A chain of includes longer than the RFC limit is a permerror."""
        spf(zone, "d0.test", "v=spf1 include:d1.test -all")
        for i in range(1, 14):
            spf(zone, f"d{i}.test", f"v=spf1 include:d{i + 1}.test -all")

        assert evaluate_spf("d0.test", "192.0.2.5")["result"] == "permerror"

    def test_two_spf_records_is_an_error(self, zone):
        zone[("example.org", "TXT")] = [
            FakeTXT("v=spf1 ip4:192.0.2.0/24 -all"),
            FakeTXT("v=spf1 -all"),
        ]

        result = evaluate_spf("example.org", "192.0.2.7")

        assert result["available"] is False
        assert "2 SPF records" in result["error"]

    def test_invalid_ip_is_reported_not_raised(self, zone):
        result = evaluate_spf("example.org", "not-an-ip")

        assert result["available"] is False
        assert "not a valid address" in result["error"]

    def test_missing_dnspython_degrades(self, monkeypatch):
        monkeypatch.setattr(dns_checks, "_get_resolver", lambda: None)

        result = evaluate_spf("example.org", "192.0.2.5")

        assert result["available"] is False
        assert "dnspython" in result["error"]


class TestLookupDmarc:
    """Test cases for lookup_dmarc."""

    def test_policy_is_parsed(self, zone):
        zone[("_dmarc.example.org", "TXT")] = [
            FakeTXT("v=DMARC1; p=reject; rua=mailto:d@example.org")
        ]

        result = lookup_dmarc("example.org")

        assert result["found"] is True
        assert result["policy"] == "reject"

    def test_monitoring_only_policy(self, zone):
        zone[("_dmarc.example.org", "TXT")] = [FakeTXT("v=DMARC1; p=none")]

        assert lookup_dmarc("example.org")["policy"] == "none"

    def test_absent_record(self, zone):
        result = lookup_dmarc("example.org")

        assert result["available"] is True
        assert result["found"] is False


class TestRunLiveChecksIsSafe:
    """run_live_checks must never raise into a request handler."""

    def test_resolver_failure_is_contained(self, monkeypatch):
        def explode():
            raise OSError("network is down")

        monkeypatch.setattr(dns_checks, "_get_resolver", explode)

        result = run_live_checks("example.org", "192.0.2.5")

        assert result["attempted"] is True
        assert result["spf"]["available"] is False


class TestReservedDomains:
    """RFC 2606 domains can never carry real mail."""

    @pytest.mark.parametrize(
        "domain", ["example.com", "example.org", "mail.example.net", "foo.test", "bar.invalid"]
    )
    def test_reserved(self, domain):
        assert is_reserved_domain(domain) is True

    @pytest.mark.parametrize("domain", ["paypal.com", "gmail.com", "spam-sender.tk"])
    def test_not_reserved(self, domain):
        assert is_reserved_domain(domain) is False


class TestLiveRulesInAnalyzer:
    """R13-R16 wiring, with the DNS layer stubbed."""

    FORGED = """
Authentication-Results: mx.gmail.com; spf=pass smtp.mailfrom=service@bank.example-real.com
Received: from mail.bank.example-real.com (mail.bank.example-real.com [45.33.32.156])
\tby mx.gmail.com with ESMTPS id abc; Mon, 15 Jan 2024 10:45:25 +0000
Message-ID: <i@bank.example-real.com>
Subject: Your invoice
From: Bank <service@bank.example-real.com>
Return-Path: <service@bank.example-real.com>
To: user@gmail.com
"""

    def stub(self, monkeypatch, spf_result, dmarc_found=True, policy="reject"):
        import app.dns_checks as module

        def fake(sender_domain, sending_ip, from_domain=""):
            return {
                "attempted": True,
                "spf": {"available": True, "result": spf_result, "record": "v=spf1 -all", "error": ""},
                "dmarc": {"available": True, "found": dmarc_found, "policy": policy,
                          "record": None, "error": ""},
            }

        monkeypatch.setattr(module, "run_live_checks", fake)

    def test_live_checks_are_off_by_default(self, monkeypatch):
        self.stub(monkeypatch, "fail")

        findings, _ = analyze(parse_headers(self.FORGED.strip() + "\n"))

        assert not [f for f in findings if f.rule_id in ("R13", "R14", "R15", "R16")]

    def test_claimed_pass_contradicted_by_dns_is_high(self, monkeypatch):
        self.stub(monkeypatch, "fail")

        findings, verdict = analyze(
            parse_headers(self.FORGED.strip() + "\n"), live_checks=True
        )
        r16 = [f for f in findings if f.rule_id == "R16"]

        assert r16 and r16[0].severity == "high"
        assert verdict == "Likely Phishing"

    def test_softfail_also_contradicts_a_claimed_pass(self, monkeypatch):
        self.stub(monkeypatch, "softfail")

        findings, _ = analyze(
            parse_headers(self.FORGED.strip() + "\n"), live_checks=True
        )

        assert "R16" in [f.rule_id for f in findings]

    def test_live_pass_raises_no_live_findings(self, monkeypatch):
        self.stub(monkeypatch, "pass")

        findings, _ = analyze(
            parse_headers(self.FORGED.strip() + "\n"), live_checks=True
        )

        assert not [f for f in findings if f.rule_id in ("R13", "R14", "R16")]

    def test_absent_spf_record_is_reported(self, monkeypatch):
        self.stub(monkeypatch, "none")

        findings, _ = analyze(
            parse_headers(self.FORGED.strip() + "\n"), live_checks=True
        )

        assert "R14" in [f.rule_id for f in findings]

    def test_missing_dmarc_is_reported(self, monkeypatch):
        self.stub(monkeypatch, "pass", dmarc_found=False)

        findings, _ = analyze(
            parse_headers(self.FORGED.strip() + "\n"), live_checks=True
        )

        assert "R15" in [f.rule_id for f in findings]

    def test_permerror_is_not_treated_as_evidence(self, monkeypatch):
        """"Cannot conclude" must never be scored as a finding."""
        self.stub(monkeypatch, "permerror")

        findings, _ = analyze(
            parse_headers(self.FORGED.strip() + "\n"), live_checks=True
        )

        assert not [f for f in findings if f.rule_id in ("R13", "R14", "R16")]
