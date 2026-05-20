# dnstoolbox — check_dns

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Maintained](https://img.shields.io/badge/maintained-yes-green.svg)](https://github.com/alan-berger/dnstoolbox/commits/main)
[![RFCs](https://img.shields.io/badge/RFCs-7208%20%7C%208461%20%7C%204034%20%7C%206698%20%7C%206844-blueviolet)](#standards--rfcs)
[![GitHub last commit](https://img.shields.io/github/last-commit/alan-berger/dnstoolbox)](https://github.com/alan-berger/dnstoolbox/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/alan-berger/dnstoolbox)](https://github.com/alan-berger/dnstoolbox/issues)
[![GitHub stars](https://img.shields.io/github/stars/alan-berger/dnstoolbox?style=social)](https://github.com/alan-berger/dnstoolbox/stargazers)

`check_dns.py` is a single-file Python tool that audits a domain's email-related DNS records and security policies, then reports each finding as **pass / warning / fail** with a one-sentence summary and actionable fix steps. It is designed to be run from the command line, on a cron schedule, or piped into a static HTML report.

It checks: **MX**, **SPF**, **DKIM**, **DMARC**, **MTA-STS**, **DNSSEC**, **DANE**, **CAA**, and **BIMI**.

---

## Features

- Nine independent checks covering inbound MX, outbound authentication (SPF/DKIM/DMARC), transport security (MTA-STS, DNSSEC, DANE), certificate-issuance restrictions (CAA), and brand indicators (BIMI).
- Three-state output (pass / warning / fail) with a colour-coded terminal view and a self-contained HTML report (no external CSS, no JavaScript, no PHP — open it directly in a browser).
- Every non-pass result includes concrete remediation steps citing the relevant RFC and example DNS records.
- Optional state tracking with **two-strike degradation alerting** via [ntfy](https://ntfy.sh) — alerts fire only after a problem is confirmed over two consecutive runs, eliminating false positives from transient resolver hiccups. Recovery notifications fire immediately on the first green result.
- Optional **JSONL audit log** appending one structured record per run for long-term analysis.
- Optional **healthchecks.io-compatible dead man's switch** to alert if the cron job itself stops running.
- Built-in SSRF protection on URLs extracted from DNS records (BIMI logo / VMC), domain-name input validation, DNS-value sanitisation, and per-record size caps.

## Standards & RFCs

| Check    | RFC(s)                          |
|----------|---------------------------------|
| MX       | RFC 5321, RFC 7505 (null MX)    |
| SPF      | RFC 7208                        |
| DKIM     | RFC 6376                        |
| DMARC    | RFC 7489                        |
| MTA-STS  | RFC 8461                        |
| DNSSEC   | RFC 4033, 4034, 4035            |
| DANE     | RFC 6698, RFC 7672 (SMTP DANE)  |
| CAA      | RFC 6844, RFC 8659              |
| BIMI     | BIMI Working Group / SVG Tiny P/S |

## Quick start

```bash
git clone https://github.com/alan-berger/dnstoolbox.git
cd dnstoolbox
pip install -r requirements.txt
python3 check_dns.py example.com
```

The first run will create a `check_dns_state.json` file next to the script for tracking subsequent state changes. Delete it any time to reset the baseline.

## Usage

```text
check_dns.py [-h] [--html] [--dkim-selectors LIST] [--permitted-cas LIST]
             [--state-file PATH] [--audit-log PATH]
             [--ntfy-url URL] [--ntfy-token TOKEN]
             [--healthcheck-url URL]
             [domain]
```

If `domain` is omitted the script prompts for it interactively.

### Common invocations

```bash
# Basic terminal report
python3 check_dns.py example.com

# Self-contained HTML report
python3 check_dns.py example.com --html > report.html

# Override DKIM selectors (default tries: default, google, selector1, selector2, k1, s1, mail, dkim)
python3 check_dns.py example.com --dkim-selectors mailer1,mailer2

# Whitelist multiple CAs for CAA checking
python3 check_dns.py example.com --permitted-cas letsencrypt.org,sectigo.com,digicert.com

# Production: HTML report + ntfy alerts + audit log + dead man's switch
python3 check_dns.py example.com --html \
    --ntfy-url https://ntfy.sh/your-topic \
    --audit-log /var/log/dns_audit.jsonl \
    --healthcheck-url https://hc-ping.com/your-uuid \
    > /var/www/html/dns-report.html
```

### Finding your DKIM selector

The script probes a list of common selectors; if none match you'll get a `missing` result for DKIM. To find the selector your provider actually uses, inspect any delivered email — the `DKIM-Signature:` header contains an `s=` tag, e.g. `s=google` or `s=protonmail3`. Pass it via `--dkim-selectors`:

```bash
python3 check_dns.py example.com --dkim-selectors protonmail3
```

## CLI reference

| Flag                  | Purpose                                                                 |
|-----------------------|-------------------------------------------------------------------------|
| `--html`              | Emit a self-contained HTML report to stdout (no external resources).    |
| `--dkim-selectors`    | Comma-separated list of DKIM selectors to probe (no spaces).            |
| `--permitted-cas`     | Comma-separated list of CA domains accepted in CAA `issue` records.     |
| `--state-file`        | Path to the JSON state file (default: `check_dns_state.json`).          |
| `--audit-log`         | Path to an append-only JSON Lines log (one entry per run).              |
| `--ntfy-url`          | ntfy topic URL for degradation / recovery alerts.                       |
| `--ntfy-token`        | Bearer token for self-hosted ntfy with access control.                  |
| `--healthcheck-url`   | URL pinged unconditionally at the end of every run (dead man's switch). |

## Output

### Terminal

Each check renders as a coloured block with status badge, one-sentence summary, raw DNS detail lines, and (when non-passing) a cyan **How to fix** section listing concrete remediation steps. A final separator and run-summary line round things off.

### HTML

`--html` writes a single standalone HTML document to stdout. Inline CSS, no external scripts or stylesheets, light + dark themes via `prefers-color-scheme`. The whole report is one file — copy it anywhere, serve as static content, or attach to email.

## Notification logic

State is persisted in a JSON file keyed by domain. On each run, every delivery-critical check (everything except BIMI) is compared against its previous value:

- **Degradation** (green → amber/red): alert fires **only after two consecutive non-green runs** originating from a green state. This eliminates false positives from transient DNS resolution issues. Repeated alerts within the same episode are suppressed.
- **Warn-to-fail** transitions (amber → red within an ongoing non-green episode): no new alert. The episode is already known.
- **Recovery** (any non-green → green): alert fires immediately on the first green result.

If no `--ntfy-url` is given, state is still tracked but no alerts are sent.

### Setting up ntfy

For the public service:

1. Pick any unguessable topic name, e.g. `dns-check-9f3a7b2e`.
2. Subscribe on phone or desktop at `https://ntfy.sh/dns-check-9f3a7b2e`.
3. Pass `--ntfy-url https://ntfy.sh/dns-check-9f3a7b2e` to the script.

For a self-hosted instance with access control, add `--ntfy-token <token>`.

## Running on a schedule

A typical cron entry (twice daily, with HTML report regeneration, alerts, audit log, and dead man's switch):

```cron
0 6,18 * * * /usr/bin/python3 /opt/dnstoolbox/check_dns.py example.com --html \
    --ntfy-url https://ntfy.sh/your-topic \
    --audit-log /var/log/dns_audit.jsonl \
    --healthcheck-url https://hc-ping.com/your-uuid \
    > /var/www/html/dns-report.html 2>> /var/log/check_dns.log
```

Two daily runs is the minimum cadence to make use of the two-strike alerting logic. The healthcheck ping notifies you if the cron itself silently breaks.

## Requirements

- Python 3.9 or newer
- `dnspython` (DNS resolution and DNSSEC support)
- `requests` (HTTP fetches for MTA-STS policy files and BIMI logos)
- `cryptography` (DANE certificate hashing — optional, only required for full DANE validation)

All listed in `requirements.txt`.

## Architecture & security notes

The script is a single file by design — easy to read, audit, and drop into any environment. A few specifics worth knowing:

- **Resolver caching is disabled.** Every query goes to the wire; this matters when iterating on DNS changes with short TTLs.
- **SSRF protection** on `BIMI l=` and `a=` URLs: only HTTPS, no IP literals, no loopback / link-local / private ranges, no `.local` / `.internal` / `.arpa`.
- **Domain input is RFC-validated** before any DNS query runs.
- **DNS values are sanitised** — non-printable characters stripped, length capped — before they reach the HTML output, in addition to standard HTML escaping.
- **The HTML report is self-contained.** No external CSS, no fonts, no scripts. Safe to serve as a static file.
- **Notification failures never abort the run.** ntfy and healthcheck errors are logged to stderr only.

## Contributing

Issues and pull requests welcome. If you're adding a check, follow the existing 4-tuple return convention (`records, status, summary, suggestions`) so it integrates with the renderers and state tracking without changes.

## License

MIT — see [LICENSE](LICENSE).
