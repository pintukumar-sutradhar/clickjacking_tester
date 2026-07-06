# Clickjacking Tester

**Clickjacking Tester** checks whether a website is vulnerable to
**clickjacking** — a technique where an attacker places a real website
inside their own page (using a hidden or disguised frame) to trick
visitors into clicking on something they didn't intend to.

Enter a website address, click **Check Website**, and get a clear result.
Optionally, click **Create & Open Demo Page** to generate a proof-of-concept
page and open it in your browser. An **Advanced options** section provides
attack style selection, page customization, manual local server control,
browser selection, and saved test management.

> **Authorized use only.** This tool is intended strictly for security
> testing you are explicitly authorized to perform (e.g. your own
> websites, or engagements covered by a signed authorization/scope).
> Do not use it against websites you do not own or do not have permission
> to test.

## Features

### Check
- Enter a website address (http/https), with automatic redirect handling.
- A clear result banner: protected, partially protected, or vulnerable.
- Technical details (final address, redirect count, status code, response
  time, raw header values) available on demand.

### Frame Protection Analysis
- **X-Frame-Options**: Missing / DENY / SAMEORIGIN / ALLOW-FROM / Invalid.
- **Content-Security-Policy**: only the `frame-ancestors` directive is
  analyzed — Missing / `'none'` / `'self'` / wildcard (`*`) / allowed
  domains / invalid.
- An explanation of why framing is allowed or blocked, including notes on
  browser support caveats (e.g. `ALLOW-FROM` being obsolete,
  `frame-ancestors` taking precedence over `X-Frame-Options` in modern
  browsers).
- No unrelated headers (cookies, TLS, HSTS, etc.) are inspected.

### Demo Page
- One-click generation and hosting of a proof-of-concept page, opened
  automatically in the default browser.
- Attack styles: Standard Iframe, Fullscreen Iframe, Transparent Iframe,
  Hidden Iframe, Overlay Attack, Fake Button Overlay, Fake Login Overlay,
  Fake Popup, Floating Iframe, Mobile/Tablet/Desktop Layout, and a blank
  Custom style.
- Customization: frame position, size, opacity; decoy overlay (button /
  login / popup) position and text; background color/image; custom HTML,
  CSS and JavaScript.
- Live preview with Desktop / Tablet / Mobile presets and zoom controls.
- Generated HTML can be copied, saved to disk, or opened from disk.

### Local Server
- An async FastAPI application served by Uvicorn in a background thread.
- Start / Stop / Restart, custom port or random available port, with
  automatic port-conflict detection.

### Browser Launch
- Open the demo page in Chrome, Firefox, Edge, or the system default,
  including opening several at once.

### Result Explanation
- A breakdown of whether the demo page is expected to load, be blocked by
  `X-Frame-Options`, be blocked by CSP `frame-ancestors`, or fail for
  other reasons.

### Saved Tests
- Save, open, and delete named test setups so a check can be resumed
  later.

### Settings
- Default browser, default port, default attack style, theme, and a full
  reset.

## Technology

- Python 3.10+
- Flet — desktop/web UI framework
- FastAPI + Uvicorn — async local demo-page hosting server
- httpx — async HTTP client
- Jinja2 — demo page HTML templating
- Pydantic — typed data models and settings
- asyncio — non-blocking checks and server operations

## Installation

```bash
cd ClickjackingTester
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
python clickjacking_tester.py
python clickjacking_tester.py --web
python clickjacking_tester.py --web --port 8550
```

## Scope

This project does not include an HTTP header checker, a security
dashboard/score, report/PDF/CSV export, a logging or scan history system,
a vulnerability database, cookie/TLS scanning, technology fingerprinting,
an OWASP dashboard, or general web vulnerability scanning. It is scoped to
clickjacking checks, demo-page creation and hosting, and header-based
frame-protection analysis.

## License

Provided for educational and authorized security-testing purposes only.
You are responsible for ensuring you have explicit permission to test any
website before using this tool against it.
