# Mailgaze Complete Guide

A comprehensive guide to understanding and working with the Mailgaze email header forensics application.

---

## Table of Contents

1. [What is Mailgaze?](#what-is-mailgaze)
2. [Project Structure](#project-structure)
3. [How I Built It](#how-i-built-it)
4. [How It Works: Step by Step](#how-it-works-step-by-step)
5. [Module Reference](#module-reference)
6. [Detection Rules (R1–R20)](#detection-rules-r1--r20)
7. [Using the Application](#using-the-application)
8. [Extending Mailgaze](#extending-mailgaze)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

---

## What is Mailgaze?

**Mailgaze** is a web application that analyzes email headers to detect phishing, spoofing, and other email-based attacks.

### Why Email Headers Matter

When you receive an email, your email client (Gmail, Outlook, etc.) shows you the basic information: who it's from, the subject, the body. But behind the scenes, there's a wealth of forensic data in the **email headers**—information that reveals:

- **Authentication results**: Did the email pass SPF, DKIM, and DMARC checks?
- **Routing history**: What servers did the email pass through? (Received chain)
- **Sender identity**: Does the "From" field match the actual email domain?
- **Suspicious patterns**: Impossible geography, long delays, keyword indicators

**Traditional email clients hide these headers by default.** Mailgaze makes header analysis accessible to everyone:

```
User's suspicious email
          ↓
"Show Original" → Copy full headers
          ↓
Paste into Mailgaze
          ↓
Get instant forensic report + verdict
```

### The Three Verdicts

- **Likely Phishing** (🔴 Red): Multiple high-risk indicators. Do not click links or download attachments.
- **Suspicious** (🟡 Yellow): Some unusual characteristics. Review before responding.
- **Likely Legitimate** (🟢 Green): Passes most checks. Still use caution with unexpected requests.

---

## Project Structure

```
mailgaze/
├── app/                          # Main application code
│   ├── __init__.py              # Package marker
│   ├── main.py                  # FastAPI routes (web server)
│   ├── parser.py                # Email header parsing
│   ├── auth_checker.py          # SPF/DKIM/DMARC parsing
│   ├── analyzer.py              # Detection rules (R1–R20)
│   ├── geo.py                   # GeoIP lookups
│   ├── explainer.py             # Plain-English explanations
│   ├── templates/               # HTML templates
│   │   ├── index.html           # Upload page
│   │   └── report.html          # Results page
│   └── static/                  # CSS and static assets
│       └── styles.css           # Styling
├── tests/
│   └── test_parser.py           # Unit tests
├── samples/
│   ├── legitimate.txt           # Sample: Gmail to Gmail (passing)
│   └── phishing.txt             # Sample: Phishing attempt
├── requirements.txt             # Python dependencies (pinned versions)
├── .env.example                 # Example environment variables
├── .gitignore                   # Git exclusions
├── run.py                       # Entry point (starts server)
├── README.md                    # Quick start guide
└── GUIDE.md                     # This file

```

### Why This Structure?

**Separation of Concerns**: Each module has one job:
- `parser.py` → Only parses headers
- `auth_checker.py` → Only reads auth results
- `analyzer.py` → Only applies rules
- `geo.py` → Only looks up IPs
- `explainer.py` → Only generates explanations
- `main.py` → Only handles HTTP routes

This makes the code easy to test, understand, and extend.

---

## How I Built It

### Design Decisions

#### 1. **FastAPI + Uvicorn** (Not Flask, Django, etc.)
- **FastAPI**: Modern Python web framework, fast, easy to read.
- **Uvicorn**: Production-grade WSGI server.
- **Why**: FastAPI is beginner-friendly, has great documentation, and is fast enough for analysis tasks.

#### 2. **Stdlib `email.parser`** (Not regex-only)
- Uses Python's built-in `email.parser.HeaderParser` to safely parse headers.
- Only uses regex for extracting IP addresses and hostnames from Received lines.
- **Why**: The stdlib parser handles edge cases and malformed headers gracefully. Regex alone is error-prone.

#### 3. **Rule-Based Analysis** (Not Machine Learning)
- 20 detection rules (R1–R20), each scoring LOW/MEDIUM/HIGH.
- Verdict determined by a simple formula (2 HIGH = phishing, etc.).
- **Why**: Transparent, deterministic, no black box. Easy for beginners to understand and debug.

#### 4. **Templated Explanations** (No external services)
- Explanations are assembled from templates keyed on the verdict and findings.
- **Why**: No API key or account to set up, works offline, and the same headers
  always produce the same explanation — which matters if a report is used as evidence.

#### 5. **No Database** (Just in-memory)
- Stateless; every request is independent.
- No persistence (no database needed).
- **Why**: Simpler, no setup, no privacy concerns about storing headers.

#### 6. **No External CSS Framework** (Custom CSS)
- Pure HTML + custom CSS (no Bootstrap, Tailwind, etc.).
- **Why**: Teaches CSS fundamentals; keeps dependencies minimal; faster load time.

---

## How It Works: Step by Step

### The User Flow

```
1. User visits http://127.0.0.1:8000
        ↓
2. Browser shows index.html (upload page)
        ↓
3. User pastes email headers (or clicks sample)
        ↓
4. User clicks "Analyze"
        ↓
5. POST /analyze route receives headers
        ↓
6. Full pipeline runs (see below)
        ↓
7. Browser shows report.html (results page)
        ↓
8. User can click "Analyze another"
```

### The Analysis Pipeline (What Happens in Step 6)

When you click "Analyze," this sequence runs:

```python
POST /analyze
    ↓
parse_headers(raw_headers)              # main.py calls parser.py
    ↓ (returns: from_, to, subject, date, received_chain, auth_results, etc.)
    ↓
analyze(parsed)                         # main.py calls analyzer.py
    ├─ read_auth_results()              # analyzer.py calls auth_checker.py
    ├─ Check all 20 rules (R1–R20)
    └─ Return: (findings[], verdict)
    ↓
explain(parsed, findings, verdict)      # main.py calls explainer.py
    └─ Build 3 paragraphs from templates
    ↓ (returns: explanation text)
    ↓
For each hop in received_chain:
    ├─ lookup_ip(hop.from_ip)           # analyzer.py calls geo.py
    └─ Get country, city, lat, lon
    ↓
Render report.html with all data
    ↓
Send to browser
```

### Example: Analyzing a Phishing Email

Let's trace through a real example:

**Input**: Phishing sample header
```
From: "PayPal Service Center" <noreply@spam-sender.tk>
Reply-To: paypal.verify@gmail.com
Subject: URGENT: Your PayPal Account Has Been Suspended — Verify Now
Authentication-Results: ... spf=fail dkim=fail dmarc=fail
Received: [12-hop chain from various servers]
```

**Parser Output**:
```python
{
    "from_": '"PayPal Service Center" <noreply@spam-sender.tk>',
    "reply_to": "paypal.verify@gmail.com",
    "subject": "URGENT: Your PayPal Account Has Been Suspended — Verify Now",
    "auth_results": "spf=fail dkim=fail dmarc=fail",
    "received_chain": [
        {"from_host": "...", "from_ip": "...", "timestamp": ...},
        ...
    ]
}
```

**Analyzer Output**:
```python
findings = [
    Finding(rule_id="R1", severity="high", title="...", description="..."),
    Finding(rule_id="R2", severity="medium", title="...", description="..."),
    Finding(rule_id="R3", severity="high", title="...", description="..."),
    Finding(rule_id="R6", severity="low", title="...", description="..."),
    Finding(rule_id="R8", severity="low", title="...", description="..."),
]
verdict = "Likely Phishing"  # 2 HIGH + other findings
```

**Explainer Output**:
```
"This email is Likely Phishing. It shows multiple warning signs...
The analysis found 5 issues:
  • Authentication checks failed or missing
  • Display name domain mismatch
  • Reply-To uses free email...
...
Recommendation: Do not click any links..."
```

**Report Display**:
- Verdict banner: RED background "Likely Phishing"
- Summary: From, To, Subject, auth badges (RED for failed)
- Received chain: 12 hops, each with geo location
- Findings: Grouped by severity (HIGH, MEDIUM, LOW)
- Explanation: Plain English text

---

## Module Reference

### 1. `parser.py` — Email Header Parsing

**What it does**: Converts raw email headers (text) into structured data (dict).

**Key Functions**:

#### `parse_headers(raw: str) -> dict`
Parses raw email headers using the stdlib `email.parser.HeaderParser`.

```python
from app.parser import parse_headers

headers = """
From: john@example.com
To: user@example.com
Subject: Hello
...
"""

parsed = parse_headers(headers)
print(parsed["from_"])      # "john@example.com"
print(parsed["subject"])    # "Hello"
print(parsed["received_chain"])  # [hop1, hop2, ...]
```

**Returns**:
```python
{
    "from_": str or None,
    "to": str or None,
    "subject": str or None,
    "date": str or None,
    "message_id": str or None,
    "reply_to": str or None,
    "return_path": str or None,
    "auth_results": str,
    "received_chain": list[dict],  # Hops
    "parse_error": str or None,  # If parsing failed
}
```

#### `parse_received_hop(line: str) -> dict`
Parses a single Received header line using regex.

```python
from app.parser import parse_received_hop

hop_line = "from mail.example.com [203.0.113.5] by recipient.example.com with ESMTP; Mon, 15 Jan 2024 08:30:00 -0800"

hop = parse_received_hop(hop_line)
print(hop["from_host"])     # "mail.example.com"
print(hop["from_ip"])       # "203.0.113.5"
print(hop["by_host"])       # "recipient.example.com"
print(hop["protocol"])      # "ESMTP"
print(hop["timestamp"])     # datetime(2024, 1, 15, 8, 30, 0, ...)
```

**Returns**:
```python
{
    "from_host": str or None,
    "from_ip": str or None,  # Validated IPv4 or IPv6
    "by_host": str or None,
    "protocol": str or None,
    "timestamp_str": str or None,
    "timestamp": datetime or None,
    "raw": str,  # Original line
}
```

**Error Handling**:
- If the header is malformed, returns a dict with `None` values (never raises).
- If you call `parse_headers("random text")`, it returns a dict with empty/None values, not an error.

---

### 2. `auth_checker.py` — Authentication Results Parsing

**What it does**: Parses the `Authentication-Results` header to extract SPF, DKIM, and DMARC results.

**Key Function**:

#### `read_auth_results(auth_results_str: str) -> dict`
Extracts SPF, DKIM, and DMARC results from an Authentication-Results header.

```python
from app.auth_checker import read_auth_results

auth_header = """spf=pass smtp.mailfrom=example.com;
dkim=pass header.d=example.com;
dmarc=pass (p=reject fo=1:d:s)"""

results = read_auth_results(auth_header)
# {
#     "spf": {"result": "pass", "detail": "smtp.mailfrom=example.com"},
#     "dkim": {"result": "pass", "detail": "header.d=example.com"},
#     "dmarc": {"result": "pass", "detail": "(p=reject fo=1:d:s)"},
# }
```

**Return Values for "result" Key**:
- `"pass"`: Authentication passed ✓
- `"fail"`: Authentication failed ✗
- `"softfail"`: Soft failure (non-fatal)
- `"neutral"`: No statement (not signed)
- `"missing"`: Header not present

**Important Note**: This parser **only reads existing results**. It does NOT perform live SPF/DKIM/DMARC checks. The mail server that received the email already did those checks and included the results in the header.

---

### 3. `analyzer.py` — Detection Rules & Verdict

**What it does**: Applies 20 forensic rules and produces findings + verdict.

**Key Class**:

#### `Finding` dataclass
Represents a single forensic finding.

```python
from app.analyzer import Finding

finding = Finding(
    rule_id="R1",
    severity="high",  # or "medium" or "low"
    title="Authentication checks failed or missing",
    description="SPF, DKIM, or DMARC is not passing. The email lacks proper authentication.",
)
```

**Key Function**:

#### `analyze(parsed: dict) -> tuple[list[Finding], str]`
Applies all 20 rules and returns findings + verdict.

```python
from app.analyzer import analyze
from app.parser import parse_headers

headers = "..."  # Raw headers
parsed = parse_headers(headers)
findings, verdict = analyze(parsed)

print(verdict)  # "Likely Phishing" or "Suspicious" or "Likely Legitimate"
for finding in findings:
    print(f"{finding.rule_id}: {finding.title} ({finding.severity})")
```

**The 10 Rules** (see detailed section below):
- R1: SPF/DKIM/DMARC missing/failed (HIGH)
- R2: Display name domain mismatch (MEDIUM)
- R3: Reply-To using free email, From is corporate (HIGH)
- R4: Return-Path domain ≠ From domain (MEDIUM)
- R5: Impossible geographic jump (HIGH)
- R6: Received chain > 8 hops (LOW)
- R7: Hop-to-hop delay > 1 hour (MEDIUM)
- R8: Subject has phishing keywords (LOW)
- R9: Date header > 24 hours from Received (MEDIUM)
- R10: Message-ID domain ≠ From domain (LOW)

**Verdict Logic**:
```python
high_count = number of HIGH severity findings
medium_count = number of MEDIUM severity findings

if high_count >= 2 or (high_count == 1 and medium_count >= 2):
    verdict = "Likely Phishing"
elif high_count == 1 or medium_count >= 3:
    verdict = "Suspicious"
else:
    verdict = "Likely Legitimate"
```

---

### 4. `geo.py` — IP Geolocation

**What it does**: Looks up the geographic location (country, city, lat, lon) of an IP address.

**Key Function**:

#### `lookup_ip(ip: str) -> dict`
Performs a GeoIP lookup on an IP address.

```python
from app.geo import lookup_ip

geo = lookup_ip("203.0.113.5")
# {"country": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194}

geo = lookup_ip("192.168.1.1")  # Private IP
# {"country": "Unknown", "city": "Unknown", "lat": None, "lon": None}

geo = lookup_ip("invalid")  # Invalid IP
# {"country": "Unknown", "city": "Unknown", "lat": None, "lon": None}
```

**Database**: Uses MaxMind's **GeoLite2-City.mmdb**
- This is a local SQLite database file (not an API call)
- If missing, returns "Unknown" gracefully
- Lazy-loads on first call (cached thereafter)

**Download GeoLite2-City.mmdb**:
```bash
# 1. Go to https://dev.maxmind.com/geoip/geolite2-city/
# 2. Register for free account
# 3. Download the .mmdb file
# 4. Place in project root: mailgaze/GeoLite2-City.mmdb
```

**Error Handling**:
- Private IPs (10.*, 192.168.*, 127.*): Returns "Unknown"
- Missing database: Returns "Unknown" (no error)
- Invalid IP: Returns "Unknown" (no error)
- Database error: Returns "Unknown" (no error)

---

### 5. `explainer.py` — Plain-English Explanations

**What it does**: Converts technical findings into plain-English explanations.

**Key Function**:

#### `explain(parsed: dict, findings: list[Finding], verdict: str) -> str`
Generates a 3+ paragraph explanation in plain English.

```python
from app.explainer import explain
from app.analyzer import Finding

findings = [
    Finding("R1", "high", "...", "..."),
    Finding("R8", "low", "...", "..."),
]
verdict = "Suspicious"

explanation = explain(parsed, findings, verdict)
print(explanation)
# Output (example):
# "This email is Suspicious. It contains some unusual characteristics...
#  
#  The analysis found 2 issue(s):
#  • High-risk issues: 1
#  • Low-risk observations: 1
#
#  Recommendation: Review the sender and the specific request carefully..."
```

**Template Structure**:
1. **Intro**: Verdict + brief statement
2. **Body**: Top 3 findings, grouped by severity
3. **Recommendation**: What the user should do

---

### 6. `main.py` — FastAPI Routes

**What it does**: Handles HTTP requests and orchestrates the pipeline.

**Routes**:

#### `GET /` → `index()`
Renders the upload page (index.html).

```python
# User visits http://127.0.0.1:8000
# Returns: HTML form for header upload
```

#### `POST /analyze` → `analyze_headers(headers: str)`
Receives headers, runs full pipeline, returns report.

```python
# User submits form with pasted headers
# 1. parse_headers(headers)
# 2. analyze(parsed)
# 3. explain(parsed, findings, verdict)
# 4. lookup_ip() for each hop
# 5. Render report.html with all data
# Returns: HTML report page
```

**Form Processing**:
- Receives `headers` from textarea (Form data)
- Processes it through the pipeline
- Passes all results to report.html template

#### `GET /sample/{name}` → `get_sample(name: str)`
Returns the raw content of a sample file (for JavaScript fetch).

```python
# Browser: fetch('/sample/phishing')
# Returns: Raw text content of samples/phishing.txt
# JavaScript: Inserts into textarea
```

**Template Rendering** (using Jinja2):
- `index.html`: Variables: request
- `report.html`: Variables: verdict, from_addr, findings, received_chain, explanation, spf/dkim/dmarc, etc.

---

## Detection Rules (R1–R20)

### Rule R1: Authentication Failed or Missing
**Severity**: HIGH  
**Trigger**: SPF, DKIM, or DMARC result is `fail`, `softfail`, or `missing`

**What it means**:
- Email servers check if the sender's domain is authorized to send emails.
- If these checks fail, it's a red flag.

**Example**:
```
Authentication-Results: spf=fail dkim=fail dmarc=fail
→ Finding: R1 (HIGH)
```

---

### Rule R2: Display Name Domain Mismatch
**Severity**: MEDIUM  
**Trigger**: From header display name doesn't match email domain

**What it means**:
- The "From" field can be spoofed: `"PayPal" <attacker@phishing.com>`
- Phishers use trusted company names with malicious email addresses.

**Example**:
```
From: "PayPal Service Center" <noreply@spam-sender.tk>
→ Display says "PayPal", domain is "spam-sender.tk"
→ Finding: R2 (MEDIUM)
```

**Exception**: Free email domains (gmail.com, yahoo.com) allow any display name, so this rule doesn't trigger for them.

---

### Rule R3: Reply-To Using Free Email, From is Corporate
**Severity**: HIGH  
**Trigger**: Reply-To uses gmail/yahoo/outlook, but From uses a non-free domain

**What it means**:
- Legitimate companies reply from their own domain.
- Phishers route replies to free email to avoid corporate infrastructure.

**Example**:
```
From: support@paypal.com
Reply-To: paypal.verify@gmail.com
→ From is corporate, Reply-To is free
→ Finding: R3 (HIGH)
```

---

### Rule R4: Return-Path Domain Mismatch
**Severity**: MEDIUM  
**Trigger**: Return-Path domain ≠ From domain

**What it means**:
- Return-Path is where bounce emails go.
- Legitimate emails have matching Return-Path and From domains.

**Example**:
```
From: john@example.com
Return-Path: noreply@attacker.com
→ Finding: R4 (MEDIUM)
```

---

### Rule R5: Impossible Geographic Jump
**Severity**: HIGH  
**Trigger**: Email travels > 5000 km in < 60 seconds

**What it means**:
- Email hops are logged with IP addresses and timestamps.
- If one hop is in Berlin and the next is in Sydney 5 seconds later, it's physically impossible.
- This suggests spoofing of Received headers.

**Example**:
```
Hop 1: from_ip=192.0.2.100 (Berlin), timestamp=08:00:00
Hop 2: from_ip=203.0.113.200 (Sydney), timestamp=08:00:05
Distance: 17000 km, Time: 5 seconds
→ Finding: R5 (HIGH)
```

**Requires**: GeoLite2-City.mmdb (otherwise skipped)

---

### Rule R6: Long Received Chain
**Severity**: LOW  
**Trigger**: Received chain has > 8 hops

**What it means**:
- Email usually goes through 3–5 hops (sender → intermediate servers → recipient).
- A 12+ hop chain is unusual but not necessarily malicious.
- Could indicate mail system issues or a redirect loop.

---

### Rule R7: Long Delay Between Hops
**Severity**: MEDIUM  
**Trigger**: Hop-to-hop time delta > 1 hour

**What it means**:
- Email usually moves fast between hops (seconds to minutes).
- A 1+ hour delay suggests the email was queued (normal) or spoofed.

---

### Rule R8: Phishing Keywords in Subject
**Severity**: LOW  
**Trigger**: Subject contains common phishing keywords

**Keywords**:
```
"urgent", "verify", "suspended", "locked", "action required",
"confirm your account", "click here", "update payment",
"unusual activity", "confirm identity", "re-activate", "reset password"
```

**Example**:
```
Subject: URGENT: Your account has been suspended — verify now
→ Contains: "urgent", "suspended", "verify"
→ Finding: R8 (LOW)
```

---

### Rule R9: Date Header Anomaly
**Severity**: MEDIUM  
**Trigger**: Date header > 24 hours different from earliest Received timestamp

**What it means**:
- The Date header should roughly match when the email was sent.
- A large discrepancy suggests spoofing.

---

### Rule R10: Message-ID Domain Mismatch
**Severity**: LOW  
**Trigger**: Message-ID registrable domain ≠ From registrable domain

**What it means**:
- Message-ID should be generated by the sending domain.
- A mismatch suggests the email wasn't actually sent by that domain.
- Subdomains are treated as a match: mail sent from `example.com` is routinely
  stamped `<id@mail.example.com>`, which is normal and is not reported.

**Example**:
```
From: john@example.com
Message-ID: <random@attacker.com>
→ Finding: R10 (LOW)

From: john@example.com
Message-ID: <abc@mail.example.com>
→ No finding (same registrable domain)
```

---

### Rule R11: Unverifiable Authentication Claim
**Severity**: HIGH  
**Trigger**: An `Authentication-Results` header is present, but it cannot be
attributed to the server that received the message

**What it means**:

This is the rule that keeps the whole authentication section honest. Mailgaze
does not perform SPF/DKIM/DMARC cryptography — it reads a header that a mail
server wrote after doing that work. But a sender controls every header in the
message they send, so anyone can type `spf=pass` into their own mail.

Only the **topmost** `Authentication-Results` header was added by the receiving
server. Everything below it arrived with the message. Mailgaze reads the topmost
header only, and trusts it only if its `authserv-id` — the name the server
stamps on its own header — shares a registrable domain with the `by` host of the
topmost `Received` hop.

When that fails, R11 fires, R1 treats the message as unauthenticated no matter
what the header claims, and the report labels the SPF/DKIM/DMARC values
"(claimed)" in grey instead of showing green passes.

**Example**:
```
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass; dmarc=pass
Received: from mail.spam-sender.tk by mx.evil-relay.tk ...

The header claims mx.gmail.com checked this message, but mx.evil-relay.tk
is what actually received it.
→ Finding: R11 (HIGH) + R1 (HIGH)  →  "Likely Phishing"
```

---

### Rule R12: Multiple Authentication Headers
**Severity**: MEDIUM  
**Trigger**: More than one `Authentication-Results` header in the message

**What it means**:
- Only the topmost was added by the receiving server.
- The others arrived with the message, and inserting a forged "pass" below the
  real header is a common way to try to fool a reader skimming the headers.
- Legitimate multi-hop mail can produce more than one, so this is MEDIUM rather
  than HIGH — it's a prompt to look, not a conviction.

**Example**:
```
Authentication-Results: mx.gmail.com; spf=fail       ← the real one
Received: ...
Authentication-Results: mx.gmail.com; spf=pass       ← inserted by the sender
→ Finding: R12 (MEDIUM); the spf=fail is what counts
```

---

## Live DNS rules (R13–R16)

Everything above reads the message and asks whether it agrees with itself. These
four rules do something different: they ask the **sender domain's own DNS**. That
is the whole point — an attacker writes the message, but they do not control the
DNS zone of the domain they are pretending to be.

They are **opt-in**. Tick "Also verify against DNS" on the form, or call
`analyze(parsed, live_checks=True)`. Off by default because they send DNS
queries for the sender's domain, which the offline path deliberately never does.

### Rule R13: Sending server not authorized (live SPF)
**Severity**: HIGH on `fail`, MEDIUM on `softfail`

The domain publishes an SPF record and that record does not authorize the IP
that delivered the message. HIGH when the domain says so strictly (`-all`),
MEDIUM when it hedges (`~all`), which large senders commonly do.

### Rule R14: Sender domain publishes no SPF record
**Severity**: MEDIUM

Nothing states which servers may send this domain's mail, so anyone can.

### Rule R15: No DMARC policy, or `p=none`
**Severity**: LOW

The domain gives receivers no instruction about failing mail, or asks only that
they monitor it. Common on small legitimate domains, hence LOW.

### Rule R16: Claim contradicted by the sender's own DNS
**Severity**: HIGH

**This is the sharpest rule in the tool.** The message asserts `spf=pass`, but
the domain's published record says the sending IP is not authorized.

Why it is strong: a genuine message from that domain evaluates to `pass`, so no
contradiction can exist. The claim comes from the message (attacker-controlled);
the record comes from DNS (not). A mismatch means someone wrote a pass that
isn't true.

Why it doesn't fire on legitimate forwarding: when a forwarder relays mail, the
*receiving server* evaluates SPF against the forwarder's IP and records the
failure. So the claim says fail and the evaluation says fail — they agree. Only
a fabricated pass produces a mismatch.

```
Authentication-Results: mx.gmail.com; spf=pass smtp.mailfrom=service@paypal.com
Received: from mail.paypal.com (mail.paypal.com [45.33.32.156]) by mx.gmail.com …

Offline:            Suspicious   (only R1 fires)
With live checks:   Likely Phishing  (R1 + R16 high, R13 medium)
```

### What the live rules deliberately do not do

- **`permerror` / `neutral` / `temperror` are never scored.** "Cannot conclude"
  is not evidence. An unsupported SPF record or a dead resolver produces no
  finding in either direction.
- **Unsupported terms fail closed.** Macros (`%{i}`) and `ptr` are not
  implemented and yield `permerror`, never a `pass`.
- **Reserved domains and addresses are skipped.** RFC 2606 domains
  (`example.com`) and RFC 1918/5737 addresses cannot carry real mail, so
  evaluating them would guarantee a meaningless failure. This is why the bundled
  samples produce no live findings.
- **The lookup budget is capped at 10** per RFC 7208, so a hostile record cannot
  make the server fan out DNS queries forever.

---

## Using the Application

### Basic Workflow

#### 1. Getting Email Headers

**Gmail**:
1. Open the suspicious email
2. Click the three-dot menu (⋮)
3. Select "Show original"
4. Copy all text (Ctrl+A → Ctrl+C)

**Outlook**:
1. Open the email
2. Click File → Properties
3. Go to "Message" tab
4. Copy the text in "Internet Headers"

**Apple Mail**:
1. Open the email
2. Menu Bar: View → Message → All Headers
3. Copy the headers

**Other**:
Look for "Show original," "View source," "Raw message," or "View headers."

#### 2. Paste into Mailgaze

1. Go to http://127.0.0.1:8000
2. Paste headers into the textarea
3. Click "Analyze"

#### 3. Read the Report

**Verdict Banner** (top):
- RED = Likely Phishing
- YELLOW = Suspicious
- GREEN = Likely Legitimate

**Email Summary**:
- From, To, Subject, Date, Reply-To, Return-Path, Message-ID

**Authentication Row**:
- SPF, DKIM, DMARC badges (color-coded)

**Received Chain** (Email Route):
- Each hop with IP, location, timestamp
- Time delays between hops

**Findings**:
- Grouped by severity (HIGH, MEDIUM, LOW)
- Each with rule ID, title, and explanation

**Explanation**:
- 3+ paragraphs in plain English
- Recommendation

---

### Testing with Samples

**Try Legitimate Email**:
1. Click "Legitimate"
2. Textarea auto-fills with a real Gmail-to-Gmail email
3. Click "Analyze"
4. **Expected**: GREEN verdict, 0–1 LOW findings

**Try Phishing Email**:
1. Go back (or reload)
2. Click "Phishing"
3. Textarea auto-fills with a realistic phishing email
4. Click "Analyze"
5. **Expected**: RED verdict, 4+ findings (HIGH and MEDIUM)

---

### Interpreting Results

#### High-Risk Findings (Red Alert)
- **R1**: Auth failed → Don't trust the sender
- **R3**: Reply-To mismatch → Likely phishing
- **R5**: Impossible geography → Header spoofing

**Action**: Don't click links, don't open attachments, don't reply with personal info.

#### Medium-Risk Findings (Yellow Alert)
- **R2**: Display name mismatch → Suspicious
- **R4**: Return-Path mismatch → Verify sender
- **R7**: Delay > 1 hour → Check if normal
- **R9**: Date anomaly → Possible spoofing

**Action**: Verify the sender through another channel (call, official website).

#### Low-Risk Findings (Green Note)
- **R6**: Long chain → Unusual but not dangerous
- **R8**: Keywords → Could be spam
- **R10**: Message-ID mismatch → Minor

**Action**: Use judgment; not always dangerous.

---

## Extending Mailgaze

### Adding a New Detection Rule

Let's say you want to add a rule: "R11: CC field is empty but shouldn't be"

**Steps**:

1. **Edit `app/analyzer.py`**:
   - Import Finding at top (already done)
   - Find the `analyze()` function
   - Add this code (before the `# ===== Compute verdict` section):

```python
# ===== Rule R11: CC field is empty =====
cc_field = parsed.get("cc")
if not cc_field or cc_field.strip() == "":
    findings.append(Finding(
        rule_id="R11",
        severity="low",
        title="No CC field present",
        description="Email has no CC field. Legitimate emails often include CC.",
    ))
```

2. **Test**:
   ```bash
   pytest tests/test_parser.py
   python run.py
   # Analyze an email; should see R11 if CC is empty
   ```

3. **Update verdict logic** if needed:
   - Currently: 2 HIGH = phishing, etc.
   - If you want R11 to affect the verdict, edit the verdict logic section

### Adding a New Field Extraction

Let's say you want to extract the `X-Originating-IP` header:

1. **Edit `app/parser.py`**, in the `parse_headers()` function:

```python
result = {
    ...
    "originating_ip": msg.get("X-Originating-IP"),  # Add this
    ...
}
```

2. **Use in analyzer** (if needed):

```python
# In app/analyzer.py
originating_ip = parsed.get("originating_ip")
if originating_ip:
    # Apply a rule based on it
    ...
```

3. **Display in report** (if needed):

```html
<!-- In app/templates/report.html -->
<dt>Originating IP:</dt>
<dd><code>{{ originating_ip }}</code></dd>
```

### Adding a New Route

Let's say you want to add a `/api/analyze` JSON endpoint:

1. **Edit `app/main.py`**:

```python
from fastapi import JSONResponse

@app.post("/api/analyze")
async def api_analyze(headers: str = Form(...)) -> JSONResponse:
    """API endpoint that returns JSON instead of HTML."""
    parsed = parse_headers(headers)
    findings, verdict = analyze(parsed)
    
    return JSONResponse({
        "verdict": verdict,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
            }
            for f in findings
        ],
    })
```

2. **Test**:
```bash
curl -X POST http://127.0.0.1:8000/api/analyze -d "headers=..." 
# Returns JSON
```

### Improving Rule Accuracy

The rules are intentionally simple. You can improve them:

- **R5 (Impossible jump)**: Currently checks > 5000 km in < 60 sec. You could adjust these thresholds.
- **R8 (Keywords)**: Add more keywords, or use ML/regex to detect variations.
- **R3 (Free email)**: Currently checks against a hardcoded list. You could fetch a live list.

---

## Troubleshooting

### Server won't start

**Error**: `Address already in use`
```
ERROR: Address already in use
```

**Fix**:
```bash
# Kill the process using port 8000
# On Windows (PowerShell):
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process -Force

# On Mac/Linux:
lsof -ti:8000 | xargs kill -9
```

Then restart: `python run.py`

---

### "ModuleNotFoundError: No module named 'geoip2'"

**Cause**: Dependencies not installed.

**Fix**:
```bash
pip install -r requirements.txt
```

---

### GeoIP lookups return "Unknown"

**Cause**: GeoLite2-City.mmdb file is missing.

**Fix**:
1. Download from https://dev.maxmind.com/geoip/geolite2-city/
2. Place in project root: `mailgaze/GeoLite2-City.mmdb`

**Note**: The app works without it; just won't show locations.

---

### Tests fail

**Error**: `FAILED tests/test_parser.py::TestParseHeaders::test_parse_legitimate_email`

**Fix**:
```bash
# Make sure you're in the right directory
cd mailgaze

# Make sure dependencies are installed
pip install pytest

# Run tests with verbose output
pytest tests/ -v -s
```

---

### Browser shows blank page

**Cause**: Templates not found.

**Fix**:
```bash
# Make sure you're in the mailgaze/ directory
ls app/templates/index.html
# Should exist; if not, create it

# Restart server
python run.py
```

---

## FAQ

### Q: Can I use Mailgaze on emails I receive?

**A**: Yes! Mailgaze is designed for this. Get the full headers from your email client and paste them in.

**Important**: Never paste the email body (text below headers), only the headers themselves.

---

### Q: Is my email being stored somewhere?

**A**: No. Mailgaze is stateless. Each analysis is independent; nothing is saved to a database or sent to an external server.

---

### Q: Can I run this on the internet (not just localhost)?

**A**: Yes, but you'd need to change the host in `run.py`:

```python
# Change this:
uvicorn.run(..., host="127.0.0.1", ...)

# To this (accessible from other machines):
uvicorn.run(..., host="0.0.0.0", ...)
```

**Warning**: Make sure you trust who has access and consider adding authentication.

---

### Q: Can I deploy this to AWS/Heroku/Google Cloud?

**A**: Yes! Mailgaze is a standard FastAPI app. You can deploy using:
- **Docker**: Create a `Dockerfile`, build, push to container registry
- **Heroku**: Git push or connect GitHub repo
- **AWS Lambda**: Use Mangum adapter for ASGI
- **Google Cloud Run**: Similar to Lambda

**Basic Dockerfile**:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "run.py"]
```

---

### Q: What about false positives?

**A**: Rules are intentionally simple to minimize false negatives (missing real phishing). Some legitimate emails might get a "Suspicious" verdict:

- Long Received chain (R6): Sometimes legitimate
- Long delays (R7): Normal in some networks
- Phishing keywords (R8): Some legit emails use these words

**Always investigate** rather than blindly trusting the verdict.

---

### Q: Can I add custom rules?

**A**: Yes! Edit `app/analyzer.py`, add your own `Finding` objects in the `analyze()` function.

See "Extending Mailgaze" section above.

---

### Q: What if an email is encrypted?

**A**: Mailgaze analyzes headers, which are always in plain text (even if the body is encrypted).

---

### Q: Can I share this with friends?

**A**: Yes! It's open-source (MIT license). You can:
- Share the GitHub link
- Modify and redistribute
- Deploy it for others to use

---

### Q: Why doesn't it verify SPF/DKIM live?

**A**: Because:
1. **Already done**: The receiving mail server (Gmail, Outlook, etc.) already verified. Including the result in the header is faster and more reliable.
2. **Privacy**: Live verification would require querying DNS, revealing that Mailgaze is analyzing this email.
3. **Complexity**: SPF/DKIM verification requires DNS lookups, DNSSEC validation, etc. The header result is sufficient.

A future version (v2) could add this as an optional feature.

---

### Q: Why Python + FastAPI instead of JavaScript/React?

**A**: 
- **Beginners**: Python is easier to learn; no build tools needed
- **Analysis**: Python has great email/text parsing libraries
- **Deployment**: Works anywhere (Windows, Mac, Linux, cloud)
- **Full-stack**: Single language for backend and frontend

---

### Q: How do I contribute?

**A**: 
1. Fork on GitHub
2. Make changes (add rules, fix bugs, improve UX)
3. Write tests
4. Submit a pull request

---

## Summary

**Mailgaze** is a beginner-friendly email header forensics tool. It:

1. **Parses** raw email headers using stdlib + regex
2. **Extracts** key fields (From, To, Subject, Received chain, auth results)
3. **Applies** 20 detection rules to spot phishing patterns
4. **Looks up** IP geolocation (optional)
5. **Generates** a verdict (Phishing / Suspicious / Legitimate)
6. **Explains** findings in plain English
7. **Displays** results in an interactive report

The code is:
- **Simple**: No black box; clear, commented code
- **Modular**: Each module has one job
- **Testable**: Unit tests for core functions
- **Extensible**: Easy to add rules, fields, or routes
- **Safe**: Graceful error handling; no data storage

**Happy analyzing!** 🔍

