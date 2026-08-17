# Mailgaze — Email Header Forensics

Analyze email headers to detect phishing, spoofing, and email-based attacks.

<!-- ─────────────────────────────────────────────────────────────────────────
     LIVE LINK GOES HERE.
     Replace the whole line below with:

     **🔗 Live demo:** https://your-space-name.hf.space

     ───────────────────────────────────────────────────────────────────── -->

**🔗 Live demo:** _not deployed yet — see [DEPLOY.md](DEPLOY.md)_

## What It Does

Mailgaze examines the forensic details in email headers — authentication results (SPF, DKIM, DMARC), routing information (Received chain), sender identity mismatches, and suspicious patterns — to produce an instant verdict on whether an email is likely phishing, suspicious, or legitimate.

## Why It Exists

Email phishing is a leading attack vector for credential theft, malware, and fraud. While email clients show minimal header information by default, the full headers contain crucial forensic clues. Mailgaze makes header analysis accessible to anyone, not just email security professionals. It's designed for:

- **Security-conscious individuals** checking suspicious emails
- **Organizations** educating staff on phishing indicators
- **Incident responders** quickly triaging email threats
- **Learning**: Understanding email security headers and forensics

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn
- **Frontend**: HTML5, CSS3 (no external frameworks)
- **Header analysis**: Stdlib `email.parser`, regex extraction
- **Body analysis**: Stdlib MIME decoding (base64, quoted-printable) to inspect links
- **Live verification**: `dnspython` — SPF evaluation and DMARC lookup against
  the sender's real DNS records (opt-in)
- **Geolocation**: MaxMind GeoIP2 (optional)
- **Explanations**: Rule-driven templates — no external services, no API keys

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   User's Browser                        │
│  index.html: Upload form → /analyze → report.html      │
└────────────────────┬────────────────────────────────────┘
                     │ POST /analyze
                     │ GET /sample/{name}
                     ▼
┌─────────────────────────────────────────────────────────┐
│                 FastAPI App (main.py)                   │
│  Routes: index, analyze, sample retrieval               │
└────────────────────┬────────────────────────────────────┘
                     │
      ┌──────────────┼──────────────────┬─────────────────┐
      ▼              ▼                  ▼                 ▼
  parser.py    auth_checker.py     analyzer.py      explainer.py
  (headers)    (SPF/DKIM/DMARC     (20 rules →      (verdict in
      │         + trust check)      findings)        plain words)
      ▼                                  │
 body_analyzer.py                        │
 (MIME decode,          ┌────────────────┴────────────────┐
  links)                ▼                                 ▼
                     geo.py                        dns_checks.py
                     (GeoIP, optional)             (live SPF/DMARC,
                                                    opt-in, R13–R16)
```

**The two that matter most for accuracy:** `auth_checker.py` decides whether an
`Authentication-Results` header can be trusted at all, and `dns_checks.py` is the
only component that consults a source the sender doesn't control.

## Install

1. **Clone or download** this repository.

2. **Create a virtual environment** (recommended):
   ```bash
   python3.11 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **(Optional) Add GeoIP database** for geographic lookups:
   - Download `GeoLite2-City.mmdb` from https://dev.maxmind.com/geoip/geolite2-city/
   - Place it in the project root directory
   - Without this file, geographic lookups will return "Unknown"

That's the whole setup — no API keys, no accounts. Mailgaze runs entirely
offline unless you tick "Also verify against DNS" on the form, which looks up
the sender's domain (see [R13–R16](#asking-dns-instead-r13r16)).

## Run

```bash
python run.py
```

Then open http://127.0.0.1:8000 in your browser.

## Putting it online

Mailgaze runs as a container and deploys free on Render or Hugging Face
Spaces — see **[DEPLOY.md](DEPLOY.md)**.


## Usage

1. **Find your email headers**:
   - **Gmail**: Open the email → click ⋮ (three dots) → "Show original"
   - **Outlook**: Open the email → File → Properties → Message → Internet Headers
   - **Apple Mail**: Open the email → View → Message → All Headers
   - **Other clients**: Look for "Show original," "View source," or "Raw message"

2. **Paste the whole thing** into the textarea — headers *and* body. "Show
   original" gives you the complete message, and there's no need to trim it:
   the header rules read the top, and the link rules (R17–R20) read the body.
   Pasting the readable message you see in your inbox will *not* work; the app
   will tell you so rather than guess.

3. **Optionally tick "Also verify against DNS"** to run rules R13–R16. This is
   the only part that can catch a well-made forgery, and the only part that
   leaves your machine — it looks up the sender's domain, nothing else.

4. **Click "Analyze"**. The report opens with a plain-language verdict, the
   evidence behind it, and what to do; the full forensic breakdown sits under
   "Show technical details".

5. **Try the samples** to see how it works:
   - Click "Legitimate" to load a passing email
   - Click "Phishing" to load a realistic phishing attempt

   Both are synthetic and use reserved domains, so the live DNS rules skip them
   deliberately — paste a real email to see those fire.

## Testing

Run the test suite:
```bash
pytest tests/
```

This runs 104 tests covering header parsing, Received chain extraction,
Authentication-Results parsing, the trust boundary on those results (including
forged and injected headers), display-name impersonation, SPF record evaluation,
DMARC policy parsing, and malformed input. DNS is faked throughout, so the suite
needs no network and takes about a second.

## How It Works (Rule-Based Analysis)

The analyzer applies 20 forensic rules — 16 offline, 4 against live DNS:

| Rule | Severity | Description |
|------|----------|-------------|
| R1   | HIGH     | SPF, DKIM, or DMARC missing or failing |
| R2   | MEDIUM   | Display name claims a brand or domain the sender doesn't match |
| R3   | HIGH     | Reply-To uses free email; From is corporate |
| R4   | MEDIUM   | Return-Path domain ≠ From domain |
| R5   | HIGH     | Impossible geographic jump in Received chain |
| R6   | LOW      | Received chain has > 8 hops |
| R7   | MEDIUM   | Hop-to-hop delay > 1 hour |
| R8   | LOW      | Subject contains phishing keywords |
| R9   | MEDIUM   | Date header > 24 hours different from Received |
| R10  | LOW      | Message-ID domain ≠ From domain (subdomains allowed) |
| R11  | HIGH     | Authentication results can't be attributed to the receiving server |
| R12  | MEDIUM   | More than one Authentication-Results header present |
| R13  | HIGH/MED | **Live SPF:** sending IP not authorized by the domain (fail / softfail) |
| R14  | MEDIUM   | **Live SPF:** sender domain publishes no SPF record |
| R15  | LOW      | **Live DMARC:** no DMARC record, or `p=none` |
| R16  | HIGH     | **Live SPF:** the message's claimed `spf=pass` is contradicted by DNS |
| R17  | HIGH     | **Link:** visible text names one destination, the link goes elsewhere |
| R18  | HIGH     | **Link:** punycode / lookalike domain |
| R19  | MEDIUM   | **Link:** points at a bare IP address instead of a domain |
| R20  | LOW      | **Link:** hidden behind a URL shortener |

Rules R13–R16 are **opt-in** — tick "Also verify against DNS" on the form. They
are the only checks that consult something outside the message.

Rules R17–R20 read the message body, which "Show original" already includes.
They cost nothing extra to run and are skipped automatically when you paste
headers alone.

**Verdict Logic**:
- **Likely Phishing**: 2+ HIGH or (1 HIGH + 2+ MEDIUM)
- **Suspicious**: 1 HIGH or 3+ MEDIUM
- **Likely Legitimate**: Otherwise

### Whose word are we taking? (R11, R12)

Mailgaze does not perform SPF/DKIM/DMARC cryptography itself — it reads the
`Authentication-Results` header that a mail server wrote after doing that work.
That makes *provenance* the whole game. A sender controls every header in the
message they send, so anyone can type `spf=pass` into their own mail.

Only the **topmost** `Authentication-Results` header was added by the server that
received the message; everything below it arrived with the message and may have
been written by the sender. Mailgaze reads the topmost header only, and trusts it
only when its `authserv-id` belongs to the same domain as the server named in the
topmost `Received` hop.

When that check fails, the reported SPF/DKIM/DMARC values are shown as **claims**
rather than results — the badges go grey and read "(claimed)" — R11 fires, and
R1 treats the message as unauthenticated regardless of what the header asserts.
R12 fires when extra `Authentication-Results` headers are present at all, since
that is a common way to try to sneak a forged "pass" past a reader.

This stops the *careless* attack: a message that simply asserts
`spf=pass; dkim=pass; dmarc=pass` about itself is reported as Likely Phishing,
not Likely Legitimate.

**It does not stop a careful one on its own** — which is what the live DNS
checks are for.

## Asking DNS instead (R13–R16)

Every offline rule reads the message and asks whether it is *internally
consistent*. That has a hard ceiling. The trust check above compares the
`authserv-id` against the `by` host of the topmost `Received` hop — but both of
those lines are part of the paste. An attacker who forges the `Received` line to
agree with the `Authentication-Results` line satisfies the check:

```
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass; dmarc=pass
Received: from mail.attacker.example (…) by mx.gmail.com with ESMTPS …
```

A genuine header written by Gmail and a forged one typed by an attacker are
byte-for-byte identical. Nothing in the text can separate them.

Ticking **"Also verify against DNS"** changes the question being asked. Instead
of trusting what the message says, Mailgaze looks up the sender domain's own SPF
record and evaluates the sending IP against it. The attacker wrote the message;
they did not write the DNS zone of the domain they are impersonating.

**R16** is the sharpest form of this: the message claims `spf=pass`, but the
domain's published record says that IP is not authorized. A genuine message
evaluates to `pass` and no contradiction exists — so the mismatch is close to
positive evidence of forgery. Legitimate forwarding does not trigger it, because
a forwarded message's *receiving server* records the SPF failure too, so the
claim and the evaluation agree.

The consistent forgery above, claiming to be `paypal.com`: **Likely Legitimate**
offline, **Likely Phishing** with DNS checks on.

### What live checks still don't give you

- **DKIM is not verified.** That is the cryptographic, truly unforgeable check,
  and it needs the message body — out of scope for a header-only tool.
- **SPF says "this server may send for this domain", not "this mail is genuine".**
  A shared provider's IP range passes SPF for every customer on it.
- **Unsupported SPF terms are `permerror`, never `pass`.** Macros and the `ptr`
  mechanism aren't implemented; a record using them yields "cannot conclude"
  rather than a guess, and is not scored either way.
- **Reserved domains and IPs are skipped.** RFC 2606 domains (`example.com`) and
  RFC 1918/5737 addresses can't carry real mail, so evaluating them would produce
  a guaranteed failure that means nothing. This is why the bundled samples show
  no live findings.

## Other limitations you must not design around

- **R5 never fires without `GeoLite2-City.mmdb`.** Without that file every hop
  resolves to "Unknown", so the impossible-geography rule silently does nothing.
- **Headers only.** Links, attachments, and body content — where most phishing
  signal actually lives — are never examined.
- **Thresholds are judgement, not calibration.** The verdict cut-offs were chosen
  by hand and have not been measured against any real corpus.
- **A clean verdict is the weakest output.** "Likely Phishing" is a useful prompt
  to look closer. "Likely Legitimate" means only that nothing in this small rule
  set fired, and should never be read as "safe" — especially with live checks
  switched off, where every input is the sender's own account of themselves.

## Roadmap (v2+)

- **DKIM verification**: Cryptographically verify the signature. This is the one
  check a forger genuinely cannot defeat, and it needs the message body as well
  as the headers.
- **SPF macro support**: Implement macro expansion so records using `%{i}` and
  friends evaluate rather than returning `permerror`.
- **Geographic map**: Visualize the Received chain on an interactive map
- **ML-based scoring**: Machine learning model for more nuanced phishing detection
- **Browser extension**: Quick header analysis from your email client
- **Mobile companion**: Native iOS/Android app
- **Batch analysis**: Upload multiple emails for bulk analysis
- **Custom rules**: Let users create and share detection rules

## License

MIT License — See LICENSE file for details.

## Contributing

Found a bug? Have an idea? Open an issue or submit a pull request on GitHub.

---

**Disclaimer**: Mailgaze is a learning and reference tool. It is not a substitute for professional email security solutions, SIEM systems, or incident response processes. Always combine header analysis with additional security controls.
