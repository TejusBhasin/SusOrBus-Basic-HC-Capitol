# SusOrBus 🛡️

**SusOrBus** is an evidence-based website safety, privacy, and risk analyzer. Paste any link before clicking to receive a transparent 0–100 risk score, verdict (`BUS`, `MILDLY SUS`, or `SUS`), granular technical evidence, tracker disclosures, terms & privacy analysis, and an isolated sandbox preview.

---

## 1. Core Mission & Scope

### What SusOrBus Does
- **Normalizes and validates URLs** strictly, preventing SSRF, port scanning, and credential leakage.
- **Inspects DNS resolutions**, verifying that all IP addresses are globally routable and blocking loopback, link-local, private RFC 1918, carrier-grade NAT, and cloud metadata services.
- **Safely fetches web pages** with byte-level bounds (1 MB cap), decompression bomb protection, strict timeouts (10s), and redirect validation.
- **Extracts structured HTML evidence**, analyzing password forms, cross-origin targets, iframes, script origin ratios, obfuscation heuristics, and pressure/scam language.
- **Inspects HTTP security headers**, including HSTS, Content-Security-Policy (CSP), X-Content-Type-Options, framing rules, and server version disclosures.
- **Identifies third-party trackers & services**, categorizing analytics, advertising, CDNs, fonts, social pixels, error monitoring, and customer support widgets.
- **Analyzes Terms of Service and Privacy Policies**, checking for data collection, cookie usage, third-party sharing, and user deletion rights.
- **Provides an isolated preview boundary**, disabling script execution to prevent drive-by attacks from untrusted targets.
- **Produces deterministic risk scores (0–100)** with explainable, deduplicated findings categorized by severity and confidence.

### What SusOrBus Does Not Do
- **Does not guarantee a site is safe**: Absence of detected threats is never proof of safety. Advanced targeted phishing and zero-days may not exhibit static signals.
- **Does not execute intrusive penetration testing**: SusOrBus never submits credentials, tests exploits, bypasses CAPTCHAs, or performs denial-of-service attacks.
- **Does not provide legal advice**: Policy text analysis identifies keyword disclosures, not legal compliance.

---

## 2. Architecture Overview

SusOrBus is structured into modular, independently testable layers:

```
[ User Input URL ]
        │
        ▼
Layer A: Input Validation & Normalization (lib/url.js)
        │
        ▼
Layer B: DNS & SSRF Protection (lib/dns.js)
        │
        ▼
Layer B: Pinned Safe Network Fetcher (lib/fetcher.js)
        ├────────────────────────┬────────────────────────┐
        ▼                        ▼                        ▼
Layer C: Static Analyzer   Layer I: Headers     Layer E: Policy Analyzer
 (lib/static-analyzer.js) (lib/security-headers) (lib/policy-analyzer.js)
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 │
                                 ▼
                 Layer D: Headless Browser Worker (Optional)
                           (lib/browser-client.js)
                                 │
                                 ▼
                 Layer F: Evidence Scoring & Deduplication
                               (lib/scorer.js)
                                 │
                                 ▼
                     Layer G: Orchestration API
                            (lib/site.js)
                                 │
        ┌────────────────────────┴────────────────────────┐
        ▼                                                 ▼
Local Server (server.js)                       Serverless API (api/check.js)
        │                                                 │
        └────────────────────────┬────────────────────────┘
                                 ▼
                 Layer H: Frontend Presentation
                           (index.html)
```

---

## 3. Finding Schema & Risk-Scoring Model

### Standard Finding Schema
Every finding adheres to a structured, explainable schema:

```json
{
  "id": "form-password-insecure-destination",
  "category": "security",
  "title": "Sensitive Form Submits Insecurely or Cross-Origin",
  "severity": "critical",
  "confidence": "high",
  "summary": "A password input is submitted to an insecure destination or different domain.",
  "evidence": "Form action: 'http://attacker.com/collect'",
  "whyItMatters": "Sending passwords over unencrypted HTTP or cross-origin indicates credential harvesting.",
  "recommendation": "Do not enter your credentials on this page.",
  "source": "Static HTML",
  "status": "detected",
  "level": "bad",
  "simple": "This page has a password field that sends your password to an unencrypted address!",
  "nerd": "Form with password input targets http://attacker.com/collect."
}
```

### Scoring Formula
The score starts at **100** (clean baseline). Deductions are calculated from deduplicated findings based on severity and confidence:

| Severity | Base Penalty | High Confidence (1.0x) | Medium (0.75x) | Low (0.5x) |
|---|---|---|---|---|
| **Critical** | 40 | -40 | -30 | -20 |
| **High** | 25 | -25 | -18.75 | -12.5 |
| **Medium** | 12 | -12 | -9 | -6 |
| **Low** | 5 | -5 | -3.75 | -2.5 |
| **Informational** | 0 | 0 | 0 | 0 |

- **Score Range**: 0 to 100
- **Verdicts**:
  - `BUS`: Score **≥ 70** (low detected risk)
  - `MILDLY SUS`: Score **40 – 69** (moderate risk / multiple warnings)
  - `SUS`: Score **< 40** (high risk / serious red flags)

---

## 4. Local Setup and Testing

### Prerequisites
- Node.js **>= 18.0.0** (v26+ recommended)
- macOS, Linux, or Windows

### Running Locally
1. Clone the repository and navigate into it:
   ```bash
   git clone https://github.com/TejusBhasin/SusOrBus-Basic-HC-Capitol.git
   cd SusOrBus-Basic-HC-Capitol
   ```
2. Start the local server:
   ```bash
   npm start
   ```
3. Open your browser at `http://127.0.0.1:3000`.

### Running Automated Tests
Run the comprehensive test suite (60+ unit, SSRF regression, and integration tests):
```bash
npm test
```

---

## 5. Environment Variables

Copy `.env.example` to configure deployment settings:

| Variable | Description | Default |
|---|---|---|
| `PORT` | Local HTTP server port | `3000` |
| `HOST` | Local HTTP binding address | `127.0.0.1` |
| `BROWSER_WORKER_URL` | Optional headless browser worker URL | `""` (static scan mode) |
| `BROWSER_WORKER_SECRET` | Bearer token for authenticating to the worker | `""` |
| `ALLOWED_ORIGIN` | CORS allowed origin | `https://tejusbhasin.github.io` |

---

## 6. Security Boundaries & SSRF Defenses

1. **URL & Scheme Pinning**: Only `http:` and `https:` schemes and ports `80` and `443` are permitted. Embedded credentials (`user:pass@`) and overlong hostnames are rejected.
2. **DNS SSRF Validation**: Every DNS A and AAAA record is verified before connection. Loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local/cloud metadata (`169.254.169.254`, `fe80::/10`), carrier-grade NAT (`100.64.0.0/10`), multicast, and IPv4-mapped IPv6 are blocked.
3. **Connection Pinning**: Outgoing sockets are pinned to the verified IP address to prevent DNS-rebinding time-of-check to time-of-use attacks.
4. **Redirect Validation**: Every redirect hop is independently parsed, re-validated, and capped at 5 redirects.
5. **Preview Isolation**: Preview responses apply `Content-Security-Policy: default-src 'self' 'unsafe-inline' data: https:; script-src 'none';` ensuring remote scripts cannot execute inside the application context.

---

## 7. Production Deployment

### Frontend on GitHub Pages
The frontend in `sus-or-bus/index.html` runs seamlessly on GitHub Pages. It queries the backend API and provides live heuristic assessments.

### Backend on Vercel
Deploy the `sus-or-bus` directory to Vercel:
- `sus-or-bus/api/check.js` serves the check endpoint.
- `sus-or-bus/api/preview.js` serves the preview endpoint.

### Optional Headless Browser Worker
Run `sus-or-bus/lib/browser-worker.js` inside an isolated container with egress rules. Set `BROWSER_WORKER_URL` and `BROWSER_WORKER_SECRET` on your Vercel deployment to activate dynamic browser observation. If not set, SusOrBus operates in static scan mode and clearly reports browser analysis as unavailable.