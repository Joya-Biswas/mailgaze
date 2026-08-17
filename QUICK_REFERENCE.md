# Mailgaze Quick Reference

Quick answers to common questions and tasks.

---

## Installation & Setup

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run the server
```bash
python run.py
```
Then open http://127.0.0.1:8000

### Run tests
```bash
pytest tests/ -v
```

### Download GeoIP database (optional)
1. Go to https://dev.maxmind.com/geoip/geolite2-city/
2. Download GeoLite2-City.mmdb
3. Place in project root

---

## Common Tasks

### Add a new detection rule

**File**: `app/analyzer.py`

**Example**: Add rule R21 "No CC field"

```python
# In the analyze() function, before "# ===== Compute verdict" section:

cc_field = parsed.get("cc")
if not cc_field:
    findings.append(Finding(
        rule_id="R21",
        severity="low",
        title="No CC field",
        description="Email has no CC. Legitimate emails often include CC.",
    ))
```

**Test**: `python run.py` → Analyze an email → Should see R21 if CC is empty.

(R11–R20 are already taken by the trust, live-DNS and link rules.)

---

### Add a new field to extract from headers

**File**: `app/parser.py`

**Example**: Extract `X-Originating-IP` header

```python
# In parse_headers(), in the result dict:

result = {
    ...
    "originating_ip": msg.get("X-Originating-IP"),  # Add this
    ...
}
```

**Use in analyzer** (if needed):
```python
# In app/analyzer.py
originating_ip = parsed.get("originating_ip")
if originating_ip:
    # Apply a rule...
```

**Display in report** (if needed):
```html
<!-- In app/templates/report.html, in summary card -->
<dt>Originating IP:</dt>
<dd><code>{{ originating_ip }}</code></dd>
```

---

### Add a new API endpoint

**File**: `app/main.py`

**Example**: Add `/api/analyze` that returns JSON

```python
@app.post("/api/analyze")
async def api_analyze(headers: str = Form(...)) -> JSONResponse:
    """API endpoint returning JSON instead of HTML."""
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

**Test**:
```bash
curl -X POST http://127.0.0.1:8000/api/analyze -d "headers=..." -H "Content-Type: application/x-www-form-urlencoded"
```

---

### Customize the verdict logic

**File**: `app/analyzer.py`

**Current logic** (in analyze() function):
```python
high_count = sum(1 for f in findings if f.severity == "high")
medium_count = sum(1 for f in findings if f.severity == "medium")

if high_count >= 2 or (high_count == 1 and medium_count >= 2):
    verdict = "Likely Phishing"
elif high_count == 1 or medium_count >= 3:
    verdict = "Suspicious"
else:
    verdict = "Likely Legitimate"
```

**Example**: Make verdict stricter (more cautious)
```python
# Only require 1 HIGH for "Likely Phishing"
if high_count >= 1:
    verdict = "Likely Phishing"
elif medium_count >= 2:
    verdict = "Suspicious"
else:
    verdict = "Likely Legitimate"
```

---

### Change the phishing keywords

**File**: `app/analyzer.py`

**In analyze() function**, R8 rule:
```python
phishing_keywords = {
    "urgent", "verify", "suspended", "locked", "action required",
    "confirm your account", "click here", "update payment", "unusual activity",
    "confirm identity", "re-activate", "reset password",
    # Add more here:
    "confirm identity", "act now", "limited time",
}
```

---

### Add a custom template variable to the report

**File**: `app/main.py`

**Example**: Add custom user message

1. **In `analyze_headers()` function**:
```python
custom_message = "This is a test analysis"

return templates.TemplateResponse(
    "report.html",
    {
        ...
        "custom_message": custom_message,  # Add this
    }
)
```

2. **In `app/templates/report.html`**:
```html
<div class="card">
    <p>{{ custom_message }}</p>
</div>
```

---

### Change colors in the UI

**File**: `app/static/styles.css`

**CSS variables** (at top):
```css
:root {
    --color-green: #16a34a;      /* Change to #00aa00 for brighter green */
    --color-yellow: #d97706;     /* Change for different yellow */
    --color-red: #dc2626;        /* Change for different red */
    --color-blue: #2563eb;       /* Change for different blue */
    --color-gray: #6b7280;
    --color-gray-light: #f3f4f6;
}
```

**Example**: Make red brighter
```css
--color-red: #ff0000;  /* Bright red */
```

---

### Add a footer link or copyright

**File**: `app/templates/report.html` (or `index.html`)

```html
<footer>
    <p>
        Made by <a href="...">You</a> •
        <a href="...">GitHub</a> •
        <a href="...">Contact</a>
    </p>
</footer>
```

---

## Troubleshooting

### Port 8000 already in use

**Error**: `Address already in use`

**Fix** (Windows PowerShell):
```powershell
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process -Force
python run.py
```

**Fix** (Mac/Linux):
```bash
lsof -ti:8000 | xargs kill -9
python run.py
```

---

### "ModuleNotFoundError: No module named..."

**Error**: `ModuleNotFoundError: No module named 'fastapi'`

**Fix**:
```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install fastapi uvicorn jinja2 python-multipart dnspython geoip2
```

---

### GeoIP lookups show "Unknown"

**Cause**: GeoLite2-City.mmdb file missing

**Fix**:
1. Download from https://dev.maxmind.com/geoip/geolite2-city/
2. Place in project root: `mailgaze/GeoLite2-City.mmdb`

**Note**: App works without it; just won't show locations.

---

### Server crashes on startup

**Check logs**:
```bash
python run.py 2>&1 | head -50
```

**Common causes**:
- Missing dependencies: `pip install -r requirements.txt`
- Invalid Python version: Use Python 3.11+
- Port already in use: See above

---

### Template not found error

**Error**: `jinja2.exceptions.TemplateNotAssertionError: index.html`

**Cause**: Templates directory missing or in wrong location

**Fix**:
```bash
# Check directory structure
ls app/templates/
# Should show: index.html report.html

# Check you're in correct directory
pwd
# Should be: .../mailgaze
```

---

### Tests fail

**Error**: `FAILED tests/test_parser.py::TestParseHeaders::test_parse_legitimate_email`

**Fix**:
```bash
# Install pytest
pip install pytest

# Run with verbose output
pytest tests/ -v -s

# Check samples exist
ls samples/
# Should show: legitimate.txt phishing.txt
```

---

## File Locations Reference

```
mailgaze/
├── app/main.py              ← Routes & orchestration
├── app/parser.py            ← Header parsing
├── app/analyzer.py          ← Detection rules
├── app/auth_checker.py      ← SPF/DKIM/DMARC parsing
├── app/geo.py               ← IP geolocation
├── app/explainer.py         ← Text explanations
├── app/templates/index.html ← Upload page
├── app/templates/report.html ← Results page
├── app/static/styles.css    ← Styling
├── samples/                 ← Sample emails
├── tests/                   ← Unit tests
├── requirements.txt         ← Dependencies
├── .env.example             ← API key template
├── run.py                   ← Start server
├── README.md                ← Quick start
├── GUIDE.md                 ← Full documentation
├── ARCHITECTURE.md          ← Technical deep dive
└── QUICK_REFERENCE.md       ← This file
```

---

## Code Snippets

### Using the parser in Python

```python
from app.parser import parse_headers
from app.analyzer import analyze

headers = open("my_email.txt").read()
parsed = parse_headers(headers)
findings, verdict = analyze(parsed)

print(f"Verdict: {verdict}")
for finding in findings:
    print(f"  {finding.rule_id}: {finding.title}")
```

---

### Using the auth checker

```python
from app.auth_checker import read_auth_results

auth_header = "spf=pass ... dkim=fail ... dmarc=pass"
results = read_auth_results(auth_header)

print(f"SPF: {results['spf']['result']}")
print(f"DKIM: {results['dkim']['result']}")
print(f"DMARC: {results['dmarc']['result']}")
```

---

### Using GeoIP lookup

```python
from app.geo import lookup_ip

geo = lookup_ip("203.0.113.5")
print(f"{geo['city']}, {geo['country']}")  # San Francisco, United States
```

---

### Running just the analyzer

```python
from app.parser import parse_headers
from app.analyzer import analyze, Finding

headers = "..."  # Raw headers
parsed = parse_headers(headers)

# Manually run analyzer
findings, verdict = analyze(parsed)

# Filter for high-severity only
high_findings = [f for f in findings if f.severity == "high"]
print(f"High-risk findings: {len(high_findings)}")
```

---

## Performance Tips

### Optimize rule R5 (geographic jump)

If GeoIP lookups are slow, skip them for certain hops:

```python
# In analyzer.py, R5 rule:
if len(received_chain) > 10:
    # Skip geo check if too many hops
    pass
else:
    # Perform geo check as usual
```

---

### Cache GeoIP results

```python
# In geo.py (already done), but you can extend:
_geoip_cache = {}

def lookup_ip(ip: str) -> dict:
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    
    result = ...  # Perform lookup
    _geoip_cache[ip] = result
    return result
```

---

## Deployment Checklists

### Local Development

- [ ] Python 3.11+ installed
- [ ] `pip install -r requirements.txt`
- [ ] `python run.py` works
- [ ] http://127.0.0.1:8000 loads
- [ ] "Legitimate" sample works
- [ ] "Phishing" sample works
- [ ] `pytest tests/ -v` passes

### Before Sharing with Others

- [ ] Review all hardcoded links (GitHub, etc.) in `templates/`
- [ ] Update README.md with your info
- [ ] Test on Windows, Mac, Linux if possible
- [ ] Run `pytest` one more time
- [ ] Create `.env.example` without your actual API key

### Docker Deployment

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t mailgaze .
docker run -p 8000:8000 mailgaze
```

---

## Version History

### v0.1.0 (Current)
- ✅ 20 detection rules (R1–R20)
- ✅ Email header parsing
- ✅ SPF/DKIM/DMARC results parsing
- ✅ GeoIP lookup (optional)
- ✅ Templated plain-English explanations
- ✅ Sample emails (legitimate + phishing)
- ✅ Unit tests

### Roadmap (v0.2+)
- 🔄 Live SPF/DKIM/DMARC verification (DNS lookups)
- 🔄 Geographic map view (Received hops on map)
- 🔄 ML-based scoring (learned from samples)
- 🔄 Browser extension (quick analysis from email client)
- 🔄 Batch analysis (upload .eml files)
- 🔄 Custom rule builder (UI for creating rules)
- 🔄 Dark mode support

---

## Getting Help

### Errors during `pip install`

1. Check Python version: `python --version` (needs 3.11+)
2. Upgrade pip: `python -m pip install --upgrade pip`
3. Try installing individually: `pip install fastapi uvicorn`

### Errors during `python run.py`

1. Check imports: `python -c "import fastapi; print(fastapi.__version__)"`
2. Check templates exist: `ls app/templates/`
3. Check port: `lsof -i :8000` (mac/linux) or `netstat -ano | findstr :8000` (windows)

### Errors during `pytest`

1. Install pytest: `pip install pytest`
2. Check samples exist: `ls samples/`
3. Run with verbose: `pytest tests/ -v -s`

---

## Contact

- **GitHub**: _add your repository URL here_
- **Issues**: _add your issue tracker URL here_
- **Discussions**: Ask questions

