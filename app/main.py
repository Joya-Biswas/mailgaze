"""
Mailgaze: FastAPI application for email header forensics.

This is the main entry point, defining routes for header analysis,
sample retrieval, and result display.
"""

import os
from pathlib import Path
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.parser import looks_like_headers, parse_headers
from app.auth_checker import evaluate_auth
from app.analyzer import analyze
from app.explainer import explain, plain_summary


# Initialize FastAPI app
app = FastAPI(title="Mailgaze", description="Email Header Forensics")

# Set up template and static file directories
app_dir = Path(__file__).parent
templates = Jinja2Templates(directory=str(app_dir / "templates"))
app.mount("/static", StaticFiles(directory=str(app_dir / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> str:
    """
    Render the main upload page (index.html).

    Users can paste email headers here or click to load a sample.
    """
    return templates.TemplateResponse(request, "index.html")


@app.post("/analyze", response_class=HTMLResponse)
async def analyze_headers(
    request: Request,
    headers: str = Form(...),
    live_checks: str = Form(default=""),
) -> str:
    """
    Accept pasted email headers, run the full analysis pipeline, and return the report.

    Args:
        request: The HTTP request (for template context).
        headers: Raw email headers from the form textarea.

    Returns:
        Rendered HTML report with findings and verdict.
    """
    # Reject input that isn't a header block at all. Pasting the readable
    # message body is the natural mistake, and it parses to an empty result —
    # rendering a verdict on that would be confidently meaningless.
    if not looks_like_headers(headers):
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "error": (
                    "Nothing in what you pasted looks like an email header. "
                    "This is usually the message body — the part you read on "
                    "screen — rather than the routing information behind it."
                ),
                "submitted": headers,
            },
            status_code=400,
        )

    # Parse the headers
    parsed = parse_headers(headers)

    # Run the analyzer. Live DNS checks are opt-in because they send queries
    # for the sender's domain, which the offline path deliberately avoids.
    use_live_checks = bool(live_checks)
    findings, verdict = analyze(parsed, live_checks=use_live_checks)

    # Generate a plain-English explanation
    explanation = explain(parsed, findings, verdict)

    # Read auth results for display, along with whether they can be attributed
    # to the receiving server. The template presents them very differently
    # depending on that, so the verdict and the badges cannot disagree.
    received = parsed.get("received_chain", [])
    auth_results = evaluate_auth(
        parsed.get("auth_results_all") or [],
        received[0].get("by_host") if received else None,
    )

    # Format the Received chain for display with geoip info
    from app.geo import lookup_ip
    received_chain_display = []
    for i, hop in enumerate(parsed.get("received_chain", [])):
        hop_display = {
            "index": i + 1,
            "from_host": hop.get("from_host", "Unknown"),
            "from_ip": hop.get("from_ip", "Unknown"),
            "by_host": hop.get("by_host", "Unknown"),
            "protocol": hop.get("protocol", "Unknown"),
            "timestamp_str": hop.get("timestamp_str", "Unknown"),
            "time_delta": None,
        }

        # Compute time delta from previous hop
        if i > 0 and hop.get("timestamp") and parsed.get("received_chain", [])[i - 1].get("timestamp"):
            prev_ts = parsed["received_chain"][i - 1]["timestamp"]
            curr_ts = hop.get("timestamp")
            delta_seconds = (prev_ts - curr_ts).total_seconds()
            hop_display["time_delta"] = format_time_delta(delta_seconds)

        # Look up geolocation
        if hop.get("from_ip"):
            geo = lookup_ip(hop.get("from_ip"))
            hop_display["geo_country"] = geo["country"]
            hop_display["geo_city"] = geo["city"]
        else:
            hop_display["geo_country"] = "Unknown"
            hop_display["geo_city"] = "Unknown"

        received_chain_display.append(hop_display)

    # Determine verdict color
    verdict_color = "red" if verdict == "Likely Phishing" else "yellow" if verdict == "Suspicious" else "green"

    # Group findings by severity
    high_findings = [f for f in findings if f.severity == "high"]
    medium_findings = [f for f in findings if f.severity == "medium"]
    low_findings = [f for f in findings if f.severity == "low"]

    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "verdict": verdict,
            "verdict_color": verdict_color,
            # "or" rather than a .get default: parse_headers always sets these
            # keys, to None when the header is absent, so a default argument
            # would never be reached and every missing field rendered as "None".
            "from_addr": parsed.get("from_") or "(not stated)",
            "to_addr": parsed.get("to") or "(not stated)",
            "subject": parsed.get("subject") or "(no subject)",
            "date": parsed.get("date") or "(not stated)",
            "reply_to": parsed.get("reply_to") or "(none)",
            "return_path": parsed.get("return_path") or "(none)",
            "message_id": parsed.get("message_id") or "(none)",
            "spf": auth_results["spf"],
            "dkim": auth_results["dkim"],
            "dmarc": auth_results["dmarc"],
            "auth_trusted": auth_results["trusted"],
            "auth_present": bool(parsed.get("auth_results_all")),
            "live_checks": use_live_checks,
            "auth_authserv": auth_results["authserv"],
            "auth_reason": auth_results["reason"],
            "received_chain": received_chain_display,
            "high_findings": high_findings,
            "medium_findings": medium_findings,
            "low_findings": low_findings,
            "explanation": explanation,
            "summary": plain_summary(findings, verdict),
        }
    )


@app.get("/sample/{name}", response_class=PlainTextResponse)
async def get_sample(name: str) -> PlainTextResponse:
    """
    Retrieve the contents of a sample email file.

    Used by the frontend to prefill the textarea when the user clicks
    "Try a sample: Legitimate" or "Try a sample: Phishing".

    Returned as plain text rather than a bare str: a bare str return would be
    JSON-encoded, which quotes the body and escapes every newline, and email
    headers are meaningless without their line breaks.

    Args:
        name: The sample name (e.g., "legitimate" or "phishing").

    Returns:
        The file contents as plain text.
    """
    # Sanitize the name to prevent directory traversal
    if not name.isalnum():
        return PlainTextResponse("Invalid sample name", status_code=400)

    sample_path = Path(__file__).parent.parent / "samples" / f"{name}.txt"

    if not sample_path.exists():
        return PlainTextResponse(f"Sample '{name}' not found", status_code=404)

    try:
        return PlainTextResponse(sample_path.read_text(encoding="utf-8"))
    except OSError as e:
        return PlainTextResponse(f"Error reading sample: {e}", status_code=500)


def format_time_delta(seconds: float) -> str:
    """
    Format a time delta in seconds as a human-readable string.

    Args:
        seconds: Number of seconds.

    Returns:
        A formatted string like "5m 30s" or "2h 15m".
    """
    if seconds is None:
        return ""

    seconds = abs(int(seconds))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts[:2])  # Limit to 2 parts for brevity
