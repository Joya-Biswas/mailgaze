"""
Generate plain-English explanations of email analysis results.

This module provides a function to explain findings and verdicts in a way
that's understandable to non-technical users. Explanations are built from
templates, so analysis stays fully offline and deterministic.
"""

from app.analyzer import Finding

# One short, jargon-free sentence per rule, written for someone who has never
# heard of SPF and does not need to. The technical wording still exists on each
# Finding; this is what gets shown first.
PLAIN_LANGUAGE = {
    "R1": "Nobody confirmed who really sent this email.",
    "R2": "The sender's name pretends to be a company the email didn't come from.",
    "R3": "Replies would go to a personal address, not the company's.",
    "R4": "The real sending address is different from the one shown.",
    "R5": "The email's route jumps between distant countries impossibly fast.",
    "R6": "The email took an unusually long route to reach you.",
    "R7": "The email sat unexplained somewhere along the way.",
    "R8": "The subject line uses pressure words common in scams.",
    "R9": "The send date doesn't match when it actually travelled.",
    "R10": "The email's internal ID doesn't match the sender.",
    "R11": "The proof of identity in this email can't be trusted — the sender may have written it themselves.",
    "R12": "This email carries more than one identity record, which is a way of hiding a fake one.",
    "R13": "The sending computer isn't one the company allows to send its email.",
    "R14": "This domain doesn't protect itself against people faking its address.",
    "R15": "This domain doesn't tell email providers to block fakes of itself.",
    "R16": "The email claims it was verified, but the company's own records say it wasn't.",
    "R17": "A link says it goes one place but actually goes somewhere else.",
    "R18": "A link uses a fake web address designed to look like a real one.",
    "R19": "A link points straight at a computer address instead of a real website.",
    "R20": "A link hides where it really goes.",
}

# What the reader should actually do, per verdict.
VERDICT_GUIDANCE = {
    "Likely Phishing": {
        "headline": "This looks like a scam",
        "eyebrow": "High risk",
        "icon": "✕",          # heavy cross
        "risk": 3,
        "action": "Don't click any links, don't download anything, and don't reply. "
                  "If it claims to be from a company you use, open their website or app "
                  "yourself instead of using anything in this email.",
        "tone": "danger",
    },
    "Suspicious": {
        "headline": "Something's off about this one",
        "eyebrow": "Be careful",
        "icon": "!",
        "risk": 2,
        "action": "Treat it carefully. If it's asking you to log in, pay, or share "
                  "details, contact the company directly through a number or website "
                  "you already trust — not through this email.",
        "tone": "warning",
    },
    "Likely Legitimate": {
        "headline": "Nothing suspicious found",
        "eyebrow": "Looks fine",
        "icon": "✓",          # check mark
        "risk": 1,
        "action": "This email passed the checks. That's reassuring but not a guarantee, "
                  "so still be careful with anything unexpected that asks for money, "
                  "passwords, or personal details.",
        "tone": "safe",
    },
}


def plain_summary(findings: list[Finding], verdict: str) -> dict:
    """
    Build a short, non-technical summary for the top of the report.

    The findings list is accurate but reads like a security report. Most people
    opening this want to know two things: is this safe, and what should I do.
    This answers those first; the technical detail stays available below.

    Args:
        findings: The Finding objects from the analyzer.
        verdict: The overall verdict string.

    Returns:
        A dict with "headline", "action", "tone", "points" and "extra_count".
    """
    guidance = VERDICT_GUIDANCE.get(verdict, VERDICT_GUIDANCE["Suspicious"])

    # Each point carries the values it rests on, so the report shows its
    # working. A claim with visible proof beside it can be checked; one
    # without just asks to be believed, and readers are right not to.
    points = [
        {
            "text": PLAIN_LANGUAGE[f.rule_id],
            "evidence": f.evidence,
            "severity": f.severity,
        }
        for f in findings
        if f.rule_id in PLAIN_LANGUAGE
    ]

    # Findings arrive sorted by severity, but those carrying visible proof make
    # the case better, so surface those first within the top few.
    ranked = sorted(points, key=lambda p: (p["evidence"] is None,))

    return {
        "headline": guidance["headline"],
        "eyebrow": guidance["eyebrow"],
        "icon": guidance["icon"],
        "risk": guidance["risk"],
        "action": guidance["action"],
        "tone": guidance["tone"],
        "points": ranked[:3],
        "total_count": len(ranked),
        "extra_count": max(0, len(ranked) - 3),
    }


def explain(parsed: dict, findings: list[Finding], verdict: str) -> str:
    """
    Generate a plain-English explanation of the email analysis results.

    Args:
        parsed: The parsed email headers dict.
        findings: List of Finding objects from the analyzer.
        verdict: The verdict string ("Likely Phishing", "Suspicious", or "Likely Legitimate").

    Returns:
        A plain-English explanation as a string (3+ paragraphs).
    """
    return _explain_with_template(parsed, findings, verdict)


def _explain_with_template(parsed: dict, findings: list[Finding], verdict: str) -> str:
    """
    Build the explanation from templates, keyed on the verdict and findings.

    Args:
        parsed: The parsed email headers dict.
        findings: List of Finding objects from the analyzer.
        verdict: The verdict string.

    Returns:
        A templated explanation string.
    """
    from_addr = parsed.get("from_", "Unknown sender")
    subject = parsed.get("subject", "(no subject)")

    # Paragraph 1: Verdict
    if verdict == "Likely Phishing":
        para1 = (
            f"This email is {verdict}. It shows multiple warning signs that suggest "
            "this message may be fraudulent or malicious. You should be very cautious."
        )
    elif verdict == "Suspicious":
        para1 = (
            f"This email is {verdict}. It contains some unusual characteristics that warrant attention. "
            "Review the details below before taking any action."
        )
    else:  # Likely Legitimate
        para1 = (
            f"This email appears {verdict}. It passed most authentication checks and shows "
            "no obvious warning signs. However, always verify unexpected requests."
        )

    # Paragraph 2: Top findings
    if findings:
        # List the worst 3 findings
        top_findings = findings[:3]
        findings_detail = "\n".join(
            f"  • {f.title}: {f.description}"
            for f in top_findings
        )

        para2 = (
            f"The analysis found {len(findings)} issue(s):\n{findings_detail}"
        )
    else:
        para2 = "The analysis found no significant issues with this email."

    # Paragraph 3: Recommendation
    if verdict == "Likely Phishing":
        para3 = (
            "Recommendation: Do not click any links or download attachments. "
            "Do not reply with personal or financial information. "
            "Report this email as phishing to your email provider."
        )
    elif verdict == "Suspicious":
        para3 = (
            "Recommendation: Review the sender and the specific request carefully. "
            "If you don't recognize the sender, contact them through a trusted channel "
            "(phone, official website) before responding."
        )
    else:  # Likely Legitimate
        para3 = (
            "Recommendation: This email likely comes from a trusted source, but always use caution. "
            "Verify unexpected requests (especially for passwords or sensitive data) through "
            "an independent channel."
        )

    return f"{para1}\n\n{para2}\n\n{para3}"
