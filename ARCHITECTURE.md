# Mailgaze Architecture Deep Dive

This document provides a detailed technical architecture of the Mailgaze application, including data flows, module relationships, and design patterns.

---

## System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         Client (Browser)                          │
│                                                                   │
│  ┌──────────────────────┐          ┌──────────────────────┐     │
│  │   index.html         │          │   report.html        │     │
│  │ (Upload Form)        │────────→ │ (Analysis Report)    │     │
│  │                      │          │                      │     │
│  │ - Textarea input     │          │ - Verdict banner     │     │
│  │ - Sample loaders     │          │ - Summary card       │     │
│  │ - Submit button      │          │ - Auth badges        │     │
│  └──────────────────────┘          │ - Hop timeline       │     │
│           │                         │ - Findings section   │     │
│           │                         │ - Explanation        │     │
│           │ POST /analyze           └──────────────────────┘     │
│           │ GET /sample/{name}                 ▲                 │
│           │                                    │                 │
└───────────┼────────────────────────────────────┼─────────────────┘
            │                                    │
            ▼                                    │
┌──────────────────────────────────────────────────────────────────┐
│                      FastAPI Server                              │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ main.py (HTTP Routes)                                    │   │
│  │                                                           │   │
│  │ ┌─────────────────┐ ┌─────────────────┐ ┌────────────┐  │   │
│  │ │ GET /           │ │ POST /analyze   │ │GET /sample │  │   │
│  │ │ index()         │ │ analyze_headers │ │ get_sample │  │   │
│  │ └────────┬────────┘ └────────┬────────┘ └────────┬───┘  │   │
│  │          │                   │                    │       │   │
│  │          └───────────────────┼────────────────────┘       │   │
│  │                              │                            │   │
│  │                 Call pipeline (orchestration)            │   │
│  │                              ▼                            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                         Pipeline                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. parse_headers(raw)                                      │  │
│  │    ↓ (parser.py)                                           │  │
│  │    Returns: parsed dict                                    │  │
│  │                                                             │  │
│  │ 2. analyze(parsed)                                         │  │
│  │    ↓ (analyzer.py + auth_checker.py + geo.py)             │  │
│  │    Returns: (findings[], verdict)                          │  │
│  │                                                             │  │
│  │ 3. explain(parsed, findings, verdict)                      │  │
│  │    ↓ (explainer.py)                                        │  │
│  │    Returns: explanation text                               │  │
│  │                                                             │  │
│  │ 4. Render templates                                        │  │
│  │    ↓ (templates + static)                                  │  │
│  │    Returns: HTML response                                  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
            │ (HTTP Response)
            │
            ▼
        Browser renders report.html
```

---

## Data Flow Diagram

### Request: User Pastes Headers and Clicks "Analyze"

```
User Input (Raw Email Headers)
    │
    ▼
┌─────────────────────────────────────────────────┐
│ parse_headers(raw: str)                        │
├─────────────────────────────────────────────────┤
│ • Uses stdlib email.parser.HeaderParser        │
│ • Extracts: from, to, subject, date, etc.      │
│ • Calls parse_received_hop() for each hop      │
│ • Returns: parsed dict                         │
└─────────────────────────────────────────────────┘
    │
    ▼
parsed = {
    "from_": "sender@example.com",
    "to": "user@example.com",
    "subject": "Hello",
    "date": "Mon, 15 Jan 2024 08:30:00 -0800",
    "received_chain": [
        {
            "from_host": "mail.example.com",
            "from_ip": "203.0.113.5",
            "by_host": "recipient.example.com",
            "protocol": "ESMTP",
            "timestamp": datetime(...),
        },
        ...
    ],
    "auth_results": "spf=pass dkim=pass dmarc=pass",
    ...
}
    │
    ▼
┌─────────────────────────────────────────────────┐
│ analyze(parsed)                                 │
├─────────────────────────────────────────────────┤
│ • read_auth_results(parsed["auth_results"])    │
│   → {"spf": {...}, "dkim": {...}, ...}        │
│                                                 │
│ • Apply 20 rules (R1–R20)                      │
│   Each rule checks parsed data & produces      │
│   Finding objects (if triggered)               │
│                                                 │
│ • For R5 (geographic jump):                    │
│   For each hop in received_chain:              │
│     lookup_ip(hop.from_ip) → geo data          │
│     Calculate distance & time delta            │
│     Check if impossible jump                   │
│                                                 │
│ • Compute verdict from findings count          │
│ • Sort findings by severity                    │
│ • Return: (findings[], verdict)               │
└─────────────────────────────────────────────────┘
    │
    ▼
findings = [
    Finding(rule_id="R1", severity="high", ...),
    Finding(rule_id="R8", severity="low", ...),
    ...
]
verdict = "Likely Phishing"
    │
    ▼
┌─────────────────────────────────────────────────┐
│ explain(parsed, findings, verdict)             │
├─────────────────────────────────────────────────┤
│ • Select verdict paragraph                     │
│ • Summarize the top 3 findings                 │
│ • Append the matching recommendation           │
│                                                 │
│ Returns: explanation string (3+ paragraphs)    │
└─────────────────────────────────────────────────┘
    │
    ▼
explanation = "This email is Likely Phishing. It shows..."
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Prepare template context dict                  │
├─────────────────────────────────────────────────┤
│ context = {                                     │
│   "verdict": "Likely Phishing",                │
│   "from_addr": "...",                          │
│   "to_addr": "...",                            │
│   "findings": [...],                           │
│   "received_chain": [...],                     │
│   "explanation": "...",                        │
│   "spf": {...},                                │
│   "dkim": {...},                               │
│   "dmarc": {...},                              │
│   ...                                          │
│ }                                              │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Render report.html with context                │
│ (Jinja2 template)                              │
├─────────────────────────────────────────────────┤
│ • HTML structure with dynamic data             │
│ • CSS styling (styles.css)                     │
│ • No JavaScript on report page (just HTML)     │
└─────────────────────────────────────────────────┘
    │
    ▼
HTTP 200 Response (HTML page)
    │
    ▼
Browser renders and displays report
```

---

## Module Dependency Graph

```
main.py (FastAPI routes)
    │
    ├─→ parser.py
    │   ├─→ email.parser (stdlib)
    │   └─→ email.utils (stdlib)
    │
    ├─→ analyzer.py
    │   ├─→ parser.py (uses parse_email_date)
    │   ├─→ auth_checker.py
    │   ├─→ geo.py
    │   └─→ math (stdlib, for haversine)
    │
    ├─→ auth_checker.py
    │   └─→ re (stdlib)
    │
    ├─→ geo.py
    │   ├─→ geoip2 (optional, from requirements.txt)
    │   └─→ ipaddress (stdlib)
    │
    ├─→ explainer.py
    │   └─→ analyzer.py (Finding type only; no external deps)
    │
    ├─→ templates/ (Jinja2)
    │   ├─→ index.html
    │   └─→ report.html
    │
    └─→ static/
        └─→ styles.css
```

**Key**: Modules only depend on modules below them (no circular dependencies).

---

## Parser Module Data Flow

```
Raw Email Headers (as string)
│
├─────────────────────────────────────┐
│ email.parser.HeaderParser           │
│ .parsestr(raw, headersonly=True)    │
└─────────────────────────────────────┘
    │
    ▼
Message object (stdlib)
    │
    ├─→ msg.get("From")
    ├─→ msg.get("To")
    ├─→ msg.get("Subject")
    ├─→ msg.get("Date")
    ├─→ msg.get("Message-ID")
    ├─→ msg.get("Reply-To")
    ├─→ msg.get("Return-Path")
    ├─→ msg.get("Authentication-Results")
    └─→ msg.get_all("Received")  ← All Received headers
         │
         For each Received line:
         ├─→ parse_received_hop(line)
         │   │
         │   ├─→ Extract "from <host> [<ip>]" via regex
         │   ├─→ Extract "by <host>" via regex
         │   ├─→ Extract "with <proto>" via regex
         │   └─→ Extract timestamp via regex
         │       └─→ parse_email_date(timestamp_str)
         │           └─→ email.utils.parsedate_to_datetime()
         │
         └─→ Add hop dict to received_chain list

Result: parsed dict with all fields
```

---

## Analyzer Module Data Flow (Rule Application)

```
parsed dict + auth_results dict
    │
    ├─── R1: Check auth_results["spf/dkim/dmarc"]
    │         If missing/fail → Finding(severity="high")
    │
    ├─── R2: Extract From display name & domain
    │         Check if display name matches domain
    │         If mismatch → Finding(severity="medium")
    │
    ├─── R3: Extract Reply-To domain & From domain
    │         If Reply-To is free and From is not
    │         → Finding(severity="high")
    │
    ├─── R4: Extract Return-Path domain & From domain
    │         If different → Finding(severity="medium")
    │
    ├─── R5: For each pair of consecutive hops:
    │         lookup_ip(prev_hop.from_ip) → geo1
    │         lookup_ip(curr_hop.from_ip) → geo2
    │         distance = haversine(geo1, geo2)
    │         time_delta = curr_time - prev_time
    │         If distance > 5000 km AND time < 60 sec
    │         → Finding(severity="high")
    │
    ├─── R6: Count received_chain length
    │         If length > 8 → Finding(severity="low")
    │
    ├─── R7: For each pair of consecutive hops:
    │         time_delta = prev_time - curr_time
    │         If time_delta > 1 hour
    │         → Finding(severity="medium")
    │
    ├─── R8: Match Subject against phishing keywords
    │         If any keyword found
    │         → Finding(severity="low")
    │
    ├─── R9: Parse Date header & find earliest Received
    │         If |Date - earliest_received| > 24 hours
    │         → Finding(severity="medium")
    │
    └─── R10: Extract Message-ID domain & From domain
              If different → Finding(severity="low")

findings[] (sorted by severity)
    │
    ▼
Verdict Logic:
    high_count = count(severity=="high")
    medium_count = count(severity=="medium")
    
    if high_count >= 2 or (high_count == 1 and medium_count >= 2):
        verdict = "Likely Phishing"
    elif high_count == 1 or medium_count >= 3:
        verdict = "Suspicious"
    else:
        verdict = "Likely Legitimate"

Result: (findings[], verdict)
```

---

## GeoIP Module Design

```
lookup_ip(ip: str) → dict
    │
    ├─ Check if private IP (10.*, 192.168.*, 127.*, ::1, etc.)
    │  If private → return {"country": "Unknown", ...}
    │
    ├─ Get GeoIP reader (lazy-load)
    │  │
    │  └─ First call:
    │     ├─ Check if GeoLite2-City.mmdb exists
    │     │  If not → return None
    │     ├─ Import geoip2.database
    │     ├─ Open reader (cached globally)
    │     └─ Return reader
    │
    ├─ reader.city(ip) → response object
    │  Try/except: On error → return {"country": "Unknown", ...}
    │
    ├─ Extract:
    │  ├─ response.country.name
    │  ├─ response.city.name
    │  ├─ response.location.latitude
    │  └─ response.location.longitude
    │
    └─ Return dict with all 4 fields
```

**Why lazy-load?**
- Loading a 60 MB database takes time
- Most requests don't need it
- Lazy-load on first call; cache thereafter

**Why is_private_ip?**
- Private IPs aren't routable; no GeoIP data
- Avoids unnecessary database lookups
- Uses stdlib `ipaddress.ip_address()` for accurate check

---

## Explainer Module

```
explain(parsed, findings, verdict)
    │
    ├─ _explain_with_template(parsed, findings, verdict)
    │  │
    │  ├─ Build 3-paragraph response:
    │  │
    │  │  Para 1 (Intro):
    │  │  ├─ If verdict == "Likely Phishing"
    │  │  │  → "This email is Likely Phishing..."
    │  │  ├─ If verdict == "Suspicious"
    │  │  │  → "This email is Suspicious..."
    │  │  └─ Else (Legitimate)
    │  │     → "This email appears Likely Legitimate..."
    │  │
    │  │  Para 2 (Findings):
    │  │  ├─ List top 3 findings
    │  │  ├─ Group by severity count
    │  │  └─ If no findings: "No significant issues"
    │  │
    │  │  Para 3 (Recommendation):
    │  │  ├─ If Phishing: "Do not click, report as phishing"
    │  │  ├─ If Suspicious: "Verify through independent channel"
    │  │  └─ If Legitimate: "Be cautious with unexpected requests"
    │  │
    │  └─ return formatted string
    │
    └─ (No API calls; fully deterministic)
```

**Why templates?**
1. Works offline — no keys, accounts, or network round-trip
2. Deterministic: the same headers always produce the same explanation, which
   matters when a report is used as evidence
3. Nothing about a user's email ever leaves the machine

---

## HTTP Request/Response Cycle

### GET /

```
Browser: GET http://127.0.0.1:8000/

FastAPI Route:
@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> str:
    return templates.TemplateResponse("index.html", {"request": request})

Response:
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

[HTML content of index.html]
```

---

### POST /analyze

```
Browser: POST /analyze
Body: application/x-www-form-urlencoded
  headers=<pasted headers>

FastAPI Route:
@app.post("/analyze", response_class=HTMLResponse)
async def analyze_headers(request: Request, headers: str = Form(...)):
    # 1. parsed = parse_headers(headers)
    # 2. findings, verdict = analyze(parsed)
    # 3. explanation = explain(parsed, findings, verdict)
    # 4. For each hop, lookup_ip()
    # 5. Build context dict
    # 6. return templates.TemplateResponse("report.html", context)

Response:
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

[HTML content of report.html with embedded data]
```

---

### GET /sample/{name}

```
Browser: GET /sample/phishing

FastAPI Route:
@app.get("/sample/{name}")
async def get_sample(name: str) -> str:
    # 1. Validate name (alphanumeric only)
    # 2. Load samples/phishing.txt
    # 3. return file.read_text()

Response:
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8

[Raw email header content]
```

---

## Template Rendering with Jinja2

### index.html

```html
<!DOCTYPE html>
<html>
<head>...header...</head>
<body>
    <div class="container">
        <h1>Mailgaze</h1>
        <form method="POST" action="/analyze">
            <textarea name="headers" ...></textarea>
            <button type="submit">Analyze</button>
            <script>
                // Fetch /sample/{name} and insert into textarea
            </script>
        </form>
    </div>
</body>
</html>
```

**No Jinja2 variables** in index.html; it's static HTML.

---

### report.html

```html
<!DOCTYPE html>
<html>
<head>...header...</head>
<body>
    <div class="verdict-banner verdict-{{ verdict_color }}">
        <h2>{{ verdict }}</h2>
    </div>
    
    <div class="summary-card">
        <dt>From:</dt>
        <dd><code>{{ from_addr }}</code></dd>
        <!-- More fields ... -->
    </div>
    
    <div class="auth-badges">
        <div class="auth-badge auth-{{ spf.result }}">
            <strong>SPF:</strong> {{ spf.result }}
        </div>
        <!-- More badges ... -->
    </div>
    
    <ol class="received-chain">
        {% for hop in received_chain %}
        <li>
            Hop {{ hop.index }}: from_ip={{ hop.from_ip }}
            Location: {{ hop.geo_city }}, {{ hop.geo_country }}
            Delay: {{ hop.time_delta }}
        </li>
        {% endfor %}
    </ol>
    
    {% for finding in high_findings %}
    <li>{{ finding.rule_id }}: {{ finding.title }}</li>
    {% endfor %}
    <!-- Similar loops for medium_findings, low_findings -->
    
    <div class="explanation">
        {{ explanation }}  <!-- Newlines preserved via CSS white-space -->
    </div>
</body>
</html>
```

**Jinja2 features used**:
- `{{ variable }}`: Insert variable
- `{% for loop %}`: Iterate
- `{% if condition %}`: Conditional

**Why Jinja2?**
- Built into FastAPI
- Simple; no compilation step
- Template variables are typed in Python

---

## Error Handling Strategy

### Parser Errors

```python
def parse_headers(raw: str) -> dict:
    try:
        # Parse using email.parser
        ...
    except Exception as e:
        return {
            "from_": None,
            "to": None,
            ...
            "parse_error": str(e),
        }
    # Never raises; always returns a dict
```

**Why?**: App should never 500-error on bad input.

---

### GeoIP Errors

```python
def lookup_ip(ip: str) -> dict:
    # If anything fails, return:
    default_result = {
        "country": "Unknown",
        "city": "Unknown",
        "lat": None,
        "lon": None,
    }
    
    # Check private IP → return default
    # Load DB → if None, return default
    # Lookup → if error, catch and return default
    # Never raises
```

**Why?**: GeoIP is optional; missing data shouldn't break the app.

---

### HTTP Errors

```python
@app.get("/sample/{name}")
async def get_sample(name: str) -> str:
    if not name.isalnum():
        return "Invalid sample name"  # Not a 404; plain text
    
    sample_path = ...
    if not sample_path.exists():
        return f"Sample '{name}' not found"  # Plain text response
    
    return sample_path.read_text()  # Success
```

**Why?**: Simple error messages; no complex error page needed.

---

## Performance Considerations

### Slow Operations

1. **GeoIP lookup**: Lazy-load + cache (done in `geo.py`)
2. **Haversine calculation**: Only for R5 rule; optimized math

### Memory Usage

- **No database**: All data in-memory, discarded after response
- **GeoIP reader**: ~60 MB, loaded once and reused
- **Received chain**: Typically 4–10 hops; negligible

### Throughput

- **Single-threaded**: Uvicorn can run multi-worker in production
- **Typical request**: Parse (1ms) + Analyze (5ms) + Explain (<1ms) + Render (1ms) = **well under 100ms**

---

## Security Considerations

### Input Validation

1. **Headers**: No validation needed; parser handles malformed gracefully
2. **Sample name**: Only alphanumeric allowed (prevents directory traversal)

### Data Privacy

- **No storage**: Headers are not saved
- **No external calls**: analysis is entirely local
- **No logging of sensitive data**: Only errors are logged

### Sandboxing

- **File access**: Limited to project directory (samples/, templates/, static/)
- **No code execution**: Headers are never eval'd or executed
- **No database**: No SQL injection possible

---

## Testing Strategy

### Unit Tests (`tests/test_parser.py`)

```
Test parsing legitimate email
    ├─ Check from, subject extracted
    └─ Check Received chain length > 0

Test parsing phishing email
    ├─ Check from, subject extracted
    └─ Check Received chain length > 8

Test parsing malformed input
    ├─ Pass random text
    └─ Check dict returned (no exception)

Test Received hop extraction
    ├─ Parse simple hop
    ├─ Parse IPv6 hop
    └─ Parse malformed hop

Test auth results extraction
    ├─ Parse spf=pass
    ├─ Parse dkim=fail
    └─ Check missing auth
```

### Integration Testing (Manual)

```
1. Start server
2. Load http://127.0.0.1:8000
3. Click "Legitimate" sample
4. Click "Analyze"
5. Check verdict == "Likely Legitimate"
6. Go back
7. Click "Phishing" sample
8. Click "Analyze"
9. Check verdict == "Likely Phishing"
10. Check findings.count >= 4
```

### Why No Framework Tests?

- Parser, analyzer, etc. are pure functions (easy unit test)
- HTTP routes are thin wrappers (manual testing sufficient)
- No database/external deps to mock

---

## Deployment Architecture

### Development (run.py)

```
python run.py
    ↓
Uvicorn server (reload=True)
    ↓
http://127.0.0.1:8000
```

### Production (Docker)

```
Dockerfile (basic)
    ↓
pip install requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
    ↓
gunicorn (or Daphne) running 4 worker processes
    ↓
Reverse proxy (nginx, CloudFlare, etc.)
    ↓
HTTPS endpoint
```

---

## Module Responsibilities

| Module | Responsibility | Dependencies |
|--------|-----------------|---|
| `main.py` | HTTP routing, orchestration | All others |
| `parser.py` | Extract headers → dict | stdlib |
| `auth_checker.py` | Parse SPF/DKIM/DMARC | stdlib (re) |
| `analyzer.py` | Apply rules → findings | parser, auth_checker, geo |
| `geo.py` | IP → location lookup | geoip2, stdlib |
| `explainer.py` | Findings → English text | none (stdlib only) |
| `templates/*` | HTML rendering | Jinja2 |
| `static/*` | CSS styling | - |

---

## Decision Log

### Why Jinja2 instead of React/Vue/Svelte?

- **Simpler for beginners**: HTML + a few template tags
- **Fewer dependencies**: No build step, no Node.js
- **Server-side rendering**: Faster; no JavaScript framework overhead
- **Type safety**: Variables typed in Python
- **Trade-off**: Can't do interactive features (but this app doesn't need them)

### Why not use a database?

- **Stateless design**: Each request is independent
- **Privacy**: No sensitive data stored
- **Deployment**: Works anywhere; no DB setup
- **Trade-off**: Can't store user's analysis history

### Why rule-based instead of ML?

- **Transparent**: You can see exactly why something triggered
- **Beginner-friendly**: No black box
- **No training data needed**: Rules work immediately
- **Trade-off**: Less adaptive; requires manual rule maintenance

### Why not perform live SPF/DKIM verification?

- **Already done**: Mail server verified; result in header
- **Privacy**: Avoid DNS leaks
- **Complexity**: Requires DNS, DNSSEC, etc.
- **Trade-off**: Can't re-verify with different policies

---

## Conclusion

Mailgaze is designed with **simplicity, clarity, and extensibility** as core principles. Each module has one job, error handling is graceful, and the data flow is linear and easy to follow. This makes it ideal for learning, extending, and maintaining over time.

