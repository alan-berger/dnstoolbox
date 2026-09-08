# dnstoolbox — check_dns

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Maintained](https://img.shields.io/badge/maintained-yes-green.svg)](https://github.com/alan-berger/dnstoolbox/commits/main)
![Checks](https://img.shields.io/badge/checks-MX%20%7C%20SPF%20%7C%20DKIM%20%7C%20DMARC%20%7C%20MTA--STS%20%7C%20DNSSEC%20%7C%20DANE%20%7C%20CAA%20%7C%20BIMI-blue)

`check_dns.py` is a single-file Python tool that audits a domain's email-related DNS records and security policies, then reports each finding as **pass / warning / fail** with a one-sentence summary and actionable fix steps. It is designed to be run from the command line, on a cron schedule, or piped into a static HTML report.

It checks: **MX**, **SPF**, **DKIM**, **DMARC**, **MTA-STS**, **DNSSEC**, **DANE**, **CAA**, and **BIMI**.

---

## Features

- Nine independent checks covering inbound MX, outbound authentication (SPF/DKIM/DMARC), transport security (MTA-STS, DNSSEC, DANE), certificate-issuance restrictions (CAA), and brand indicators (BIMI).
- Three-state output (pass / warning / fail) with a colour-coded terminal view and a self-contained HTML report (no external CSS, no JavaScript, no PHP — open it directly in a browser).
- Every non-pass result includes concrete remediation steps citing the relevant RFC and example DNS records.
- **Provider-aware DANE checking.** Remediation depends on who operates the zone the TLSA record must live in, so a domain on Microsoft 365 or Google Workspace is told what it can actually do rather than being handed TLSA publication steps it cannot use. See [DANE checking](#dane-checking).
- Optional state tracking with **two-strike degradation alerting** via [ntfy](https://ntfy.sh) — alerts fire only after a problem is confirmed over two consecutive runs, eliminating false positives from transient resolver hiccups. Recovery notifications fire immediately on the first green result.
- Optional **JSONL audit log** appending one structured record per run for long-term analysis.
- Optional **healthchecks.io-compatible dead man's switch** to alert if the cron job itself stops running.
- Built-in SSRF protection on URLs extracted from DNS records (BIMI logo / VMC), domain-name input validation, DNS-value sanitisation, and per-record size caps.

## Standards & RFCs

| Check    | RFC(s)                            |
|----------|-----------------------------------|
| MX       | RFC 5321, RFC 7505 (null MX)      |
| SPF      | RFC 7208                          |
| DKIM     | RFC 6376                          |
| DMARC    | RFC 7489                          |
| MTA-STS  | RFC 8461                          |
| DNSSEC   | RFC 4033, 4034, 4035              |
| DANE     | RFC 6698, RFC 7671, RFC 7672 (SMTP DANE) |
| CAA      | RFC 6844, RFC 8659                |
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
             [--dane-strict] [--dane-self-hosted] [--dane-mx-limit N]
             [--list-providers]
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

# Show which mail providers the DANE check recognises
python3 check_dns.py --list-providers

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
| `--dane-strict`       | Grade a missing TLSA record as FAIL even where the provider offers no DANE and the domain owner has no available action. Default is WARNING. |
| `--dane-self-hosted`  | Treat MX hosts outside the checked domain as zones you operate (e.g. `example.com` with MX `mail.example.net`). Forces TLSA publication guidance. |
| `--dane-mx-limit N`   | Maximum MX hosts to check for DANE, in preference order. `0` checks all. Default: `5`. |
| `--list-providers`    | Print the mail providers recognised by the DANE check and exit.         |

## DANE checking

DANE is the most involved check in the tool, because a correct answer depends on facts the DNS alone does not make obvious.

### TLSA records live in the MX host's zone, not yours

A TLSA record is published at `_25._tcp.<mx-hostname>`, in whatever zone contains that hostname. If your MX points at `example-com.mail.protection.outlook.com`, that zone belongs to Microsoft — nothing you publish in your own zone has any effect. Telling such a domain to "add a TLSA record" is unactionable advice.

The check therefore works out who operates the relevant zone:

- **Self-hosted MX** (inside the checked domain, or forced with `--dane-self-hosted`) → TLSA publication steps, preceded by a DNSSEC warning if the zone is unsigned.
- **Hosted MX** → provider-appropriate guidance. For Microsoft 365 on a legacy endpoint that means the migration to `*.mx.microsoft` (`Enable-DnssecForVerifiedDomain`, MX cutover, `Enable-SmtpDaneInbound`). For Google Workspace it means saying plainly that no action exists and pointing at MTA-STS instead.

Feasibility is decided from evidence, not from a lookup table: the tool locates the zone cut containing the MX hostname (via the SOA in the authority section of a NODATA response) and probes it for DNSKEY. An unsigned zone cannot carry usable TLSA records, whoever runs it. The provider table supplies **names and vendor-specific procedures only**, so it degrades to correct-but-generic guidance rather than to confidently wrong instructions when a vendor changes their offering.

24 providers are recognised. Inbound DANE posture is asserted for only 5 of them, where it has been verified; the other 19 are listed so the report can name the provider, and the runtime DNSSEC probe answers the feasibility question. `--list-providers` prints the distinction.

### Every MX host is checked

DANE applies per MX host (RFC 7672 §2.2). A sender may select any MX, and if the one it picks has no TLSA record it falls back to opportunistic TLS for that delivery. The overall status is therefore the **worst** of the per-host results, and a domain with a pinned primary and an unpinned backup is reported as a failure — the backup is a downgrade path an attacker can force by blocking the primary.

Hosts with identical findings collapse into a single reporting block, so Google's five MX hosts produce one entry rather than five copies of the same paragraph.

### TLSA records are a set of alternatives, and usage matters

A host's TLSA records are alternatives: the host is authenticated if **any** usable record matches. Providers that rotate keys publish several on purpose and expect some not to match — Microsoft documents exactly this. Checking only the first record produces false failures on correctly configured hosts.

Records are validated according to their certificate usage field:

| Usage | Name    | How it is checked                                                     |
|-------|---------|-----------------------------------------------------------------------|
| 3     | DANE-EE | Compared against the end-entity certificate the server presents.       |
| 2     | DANE-TA | Compared against every certificate in the chain the server presents.   |
| 0, 1  | PKIX-TA / PKIX-EE | Reported and excluded — RFC 7672 §3.1.3 requires SMTP clients to ignore them. |

### Certificate retrieval

The server's certificate is fetched over SMTP with STARTTLS using `smtplib`, which performs the `EHLO` that RFC 5321 requires before `STARTTLS` and frames multi-line responses correctly. Certificate verification is deliberately disabled during the fetch: DANE-EE pins the certificate itself and is routinely used with certificates that do not chain to a public root, so PKIX validation here would reject valid deployments. The certificate is being fetched to hash it, not to make a trust decision.

Each MX host with a TLSA record costs one SMTP connection on port 25. Lower `--dane-mx-limit` if that matters on a scheduled run.

### Known limitations

- **DANE-TA chain-path validation is not performed.** For usage 2 the tool confirms the pinned anchor is *present* in the chain the server sent; it does not verify that the leaf actually chains to that anchor (RFC 7671 §5.2.2 — signatures, validity, basic constraints). A misordered or broken chain containing the right anchor would pass here and fail at a real sender.
- **Chain retrieval is Python-version dependent.** `SSLSocket.get_unverified_chain()` is public from Python 3.13; earlier versions are handled through the equivalent private accessor. Where neither is available the DANE-TA records are reported as *not verified* — with the reason stated — and grade WARNING, never FAIL.
- **Outbound port 25 must be open.** Many cloud providers and consumer ISPs block it. The tool distinguishes this failure from a genuine fault and says so.
- Only SMTP on port 25 (`_25._tcp`) is checked. Submission ports are out of scope.

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

## Upgrading from an earlier version

The DANE check now grades some situations differently, so **delete `check_dns_state.json`** (or the entry for the affected domain) on first run after upgrading. Two cases change:

- A hosted MX with no available DANE option now reports WARNING rather than FAIL, unless `--dane-strict` is set.
- A domain with partial TLSA coverage across its MX hosts now reports FAIL where it previously passed on the strength of the primary alone.

Carrying the old state forward is harmless for reporting, but the stored `notified` flag from a previous episode can suppress the alert on the next genuine degradation.

## Requirements

- Python 3.9 or newer (3.13+ additionally enables DANE-TA chain verification)
- `dnspython` (DNS resolution and DNSSEC support)
- `requests` (HTTP fetches for MTA-STS policy files and BIMI logos)
- `cryptography` (DANE certificate hashing — optional, only required for full DANE validation)

All listed in `requirements.txt`. No dependencies were added by the DANE work: SMTP handling uses `smtplib` from the standard library.

## Architecture & security notes

The script is a single file by design — easy to read, audit, and drop into any environment. A few specifics worth knowing:

- **Resolver caching is disabled.** Every query goes to the wire; this matters when iterating on DNS changes with short TTLs.
- **SSRF protection** on `BIMI l=` and `a=` URLs: only HTTPS, no IP literals, no loopback / link-local / private ranges, no `.local` / `.internal` / `.arpa`.
- **Domain input is RFC-validated** before any DNS query runs.
- **DNS values are sanitised** — non-printable characters stripped, length capped — before they reach the HTML output, in addition to standard HTML escaping.
- **The HTML report is self-contained.** No external CSS, no fonts, no scripts. Safe to serve as a static file.
- **Notification failures never abort the run.** ntfy and healthcheck errors are logged to stderr only.
- **Zone-cut detection uses the SOA in the authority section** of a NODATA response rather than walking labels upward, which would find a signed TLD above an unsigned provider zone and report a false positive. Where the apex cannot be determined the tool says so rather than guessing.

## Contributing

Issues and pull requests welcome. If you're adding a check, follow the existing 4-tuple return convention (`records, status, summary, suggestions`) so it integrates with the renderers and state tracking without changes.

Adding a mail provider to the DANE table is a small, self-contained change: add an entry to `_MAIL_PROVIDERS` with the MX suffixes and, if their inbound DANE posture is genuinely known, the appropriate `inbound_dane` value and guidance. If it is not known, leave `inbound_dane` as `'unknown'` with empty guidance — the report will still name the provider, and the runtime DNSSEC probe supplies the rest. Please don't assert a vendor posture without a source.

## License

MIT — see [LICENSE](LICENSE).
