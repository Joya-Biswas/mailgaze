"""
Unit tests for the Authentication-Results parser and the resulting verdicts.

These cover the real-world header shapes that RFC 7601 permits — parenthesized
comments and trailing property/value pairs after the result token — which a
stricter reading of the grammar misses entirely.
"""

from pathlib import Path

from app.analyzer import analyze
from app.auth_checker import read_auth_results
from app.parser import parse_headers

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def load_sample(name: str) -> str:
    """Load a sample email from the samples directory."""
    return (SAMPLES_DIR / f"{name}.txt").read_text(encoding="utf-8")


class TestReadAuthResults:
    """Test cases for read_auth_results."""

    def test_missing_header(self):
        """An absent or blank header reports every method as missing."""
        for value in ("", "   ", None):
            result = read_auth_results(value or "")
            assert result["spf"]["result"] == "missing"
            assert result["dkim"]["result"] == "missing"
            assert result["dmarc"]["result"] == "missing"

    def test_simple_semicolon_separated(self):
        """The plainest form: result token followed directly by a semicolon."""
        header = "mx.example.com; spf=pass; dkim=fail; dmarc=none"

        result = read_auth_results(header)

        assert result["spf"]["result"] == "pass"
        assert result["dkim"]["result"] == "fail"
        assert result["dmarc"]["result"] == "none"

    def test_result_followed_by_comment(self):
        """
        A parenthesized comment after the result must not hide it.

        This is the common Gmail/Google Workspace shape.
        """
        header = (
            "mx.gmail.com; "
            "spf=pass (google.com: domain of s@example.com designates "
            "203.0.113.5 as permitted sender) smtp.mailfrom=s@example.com; "
            "dmarc=pass (p=reject fo=1:d:s) header.from=example.com;"
        )

        result = read_auth_results(header)

        assert result["spf"]["result"] == "pass"
        assert result["dmarc"]["result"] == "pass"

    def test_result_followed_by_properties(self):
        """Trailing property/value pairs must not hide the result either."""
        header = "mx.example.com; dkim=pass header.d=example.com header.s=default"

        result = read_auth_results(header)

        assert result["dkim"]["result"] == "pass"
        assert "header.d=example.com" in result["dkim"]["detail"]

    def test_detail_stops_at_clause_boundary(self):
        """One method's detail must not swallow the next method's clause."""
        header = (
            "mx.example.com;\n"
            "       dkim=pass header.d=example.com\n"
            "       dmarc=fail header.from=other.com;"
        )

        result = read_auth_results(header)

        assert result["dkim"]["result"] == "pass"
        assert "dmarc" not in result["dkim"]["detail"]
        assert result["dmarc"]["result"] == "fail"

    def test_dkim_adsp_does_not_match_dkim(self):
        """A different method with 'dkim' as a prefix must not be picked up."""
        header = "mx.example.com; dkim-adsp=none; spf=fail smtp.mailfrom=x@y.com"

        result = read_auth_results(header)

        assert result["dkim"]["result"] == "missing"
        assert result["spf"]["result"] == "fail"

    def test_case_insensitive(self):
        """Method names and results are matched regardless of case."""
        result = read_auth_results("mx.example.com; SPF=Pass; DKIM=PASS")

        assert result["spf"]["result"] == "pass"
        assert result["dkim"]["result"] == "pass"

    def test_legitimate_sample_passes_all_three(self):
        """The bundled legitimate sample authenticates cleanly."""
        parsed = parse_headers(load_sample("legitimate"))

        result = read_auth_results(parsed["auth_results"] or "")

        assert result["spf"]["result"] == "pass"
        assert result["dkim"]["result"] == "pass"
        assert result["dmarc"]["result"] == "pass"


class TestSampleVerdicts:
    """End-to-end verdicts for the bundled samples."""

    def test_legitimate_sample_verdict(self):
        """The legitimate sample must not be flagged as phishing."""
        parsed = parse_headers(load_sample("legitimate"))

        findings, verdict = analyze(parsed)

        assert verdict == "Likely Legitimate"
        # R1 fires on missing/failing auth; it must not fire here.
        assert "R1" not in [f.rule_id for f in findings]

    def test_phishing_sample_verdict(self):
        """The phishing sample trips the authentication rule and more."""
        parsed = parse_headers(load_sample("phishing"))

        findings, verdict = analyze(parsed)

        assert verdict == "Likely Phishing"
        assert "R1" in [f.rule_id for f in findings]
