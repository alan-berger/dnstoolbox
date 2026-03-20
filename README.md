# DNS Email Security Checker

A Python command-line tool that performs comprehensive validation of email-related DNS records and security policies. Results are presented with a traffic light system — green, amber, red — each accompanied by a plain-English explanation of the result and, where applicable, actionable suggestions for remediation.

The tool can output directly to the terminal or produce a self-contained HTML report suitable for hosting on a website. Combined with a cron job, it provides continuous monitoring with push notifications via [ntfy](https://ntfy.sh) when a delivery-critical check degrades from green, and a recovery alert when it returns to green.

---

## Checks Performed

| Check | What is validated |
|---|---|
| **MX** | Mail exchange records are present and the domain can receive email |
| **SPF** | Record is present, well-formed, and within the 10 DNS lookup limit (RFC 7208) |
| **DKIM** | Signing keys are present for the tested selectors |
| **DMARC** | Policy is present, enforcement level, and SPF/DKIM alignment strictness |
| **MTA-STS** | DNS record, policy file reachability, mode, max_age validity, and MX alignment |
| **BIMI** | DNS record, VMC presence, logo reachability, and full SVG Tiny P/S compliance |

---

## Traffic Light System

Every check is assigned one of three statuses:

| Colour | Meaning |
|---|---|
| 🟢 **Green — PASS** | Correctly configured; no action needed |
| 🟡 **Amber — WARNING** | Present but suboptimal; security could be improved |
| 🔴 **Red — FAIL** | Missing or critically misconfigured; immediate attention recommended |

Non-green results include a "How to fix" section with specific, actionable steps to resolve the issue.

---

## Requirements

- Python 3.8 or later
- [`dnspython`](https://www.dnspython.org/)
- [`requests`](https://requests.readthedocs.io/)

No other third-party dependencies are required. The HTML report and all notification logic use Python's standard library only.

---

## Installation

```bash
git clone https://github.com/alan-berger/dnstoolbox.git
cd dnstoolbox
pip install dnspython requests
```

Make the script executable if you intend to run it directly:

```bash
chmod +x check_dns.py
```

---

## Usage

### Terminal output

Pass the domain as an argument:

```bash
python3 check_dns.py example.com
```

Or run interactively and enter the domain when prompted:

```bash
python3 check_dns.py
```

### HTML report

Add the `--html` flag and redirect stdout to a file:

```bash
python3 check_dns.py example.com --html > report.html
```

The output is a fully self-contained HTML file with no external dependencies — all styling is inline CSS. It can be opened directly in a browser, served as a static file, or embedded into an existing web page.

---

## Command-Line Arguments

| Argument | Default | Description |
|---|---|---|
| `domain` | prompted | Domain name to check |
| `--html` | off | Output a self-contained HTML report to stdout instead of terminal output |
| `--state-file PATH` | `check_dns_state.json` | Path to the JSON state file used for regression detection. Created automatically on first run |
| `--audit-log PATH` | none | Path to an append-only JSON lines file recording every check result on every run |
| `--ntfy-url URL` | none | ntfy topic URL for push notifications on status changes |
| `--healthcheck-url URL` | none | healthchecks.io-compatible ping URL, sent at the end of every successful run |

---

## Push Notifications via ntfy

The script integrates with [ntfy](https://ntfy.sh) to deliver push notifications to your phone or desktop when a delivery-critical check degrades from green, and again when it recovers.

### Which checks trigger notifications

Only checks that directly affect email deliverability are monitored for notifications. BIMI is intentionally excluded as it affects branding only, not delivery.

| Check | Notified |
|---|---|
| MX Records | Yes |
| SPF Record | Yes |
| DKIM Record | Yes |
| DMARC Record | Yes |
| MTA-STS Record | Yes |
| BIMI Record | No |

### Notification rules

**Degradation alert** — fires when a check moves from green to amber or red, confirmed over **2 consecutive runs**. The two-run threshold eliminates false positives caused by transient DNS timeouts or brief network hiccups. A single bad result is silently absorbed; a second consecutive bad result triggers the alert.

Note that amber → red transitions do not trigger a new notification. The alert fired when the check first left green; you are already aware of the issue.

**Recovery alert** — fires immediately on the first run where a previously non-green check returns to green. No threshold applies — recovery is always notified on the first confirmation.

### ntfy priority mapping

| Status | ntfy Priority |
|---|---|
| Degraded to amber | Default (3) |
| Degraded to red | High (4) |
| Recovered to green | Low (2) |

ntfy's `Tags` header is also set per status, which renders as an emoji prefix in the notification list view in the ntfy app.

Refer to the [ntfy documentation](https://docs.ntfy.sh/publish/#message-priority) for how priority levels affect notification behaviour on iOS and Android.

### Setting up ntfy

1. Install the ntfy app on your device ([iOS](https://apps.apple.com/app/ntfy/id1625396347) / [Android](https://play.google.com/store/apps/details?id=io.heckel.ntfy)).
2. Choose a topic name. Because ntfy.sh topics are public and unauthenticated by default, **use a long pseudorandom string** (64 characters is recommended) rather than a memorable name. Anyone who knows your topic name can read your notifications.
3. Subscribe to the topic in the ntfy app.
4. Pass the full topic URL to the script:

```bash
python3 check_dns.py example.com --ntfy-url https://ntfy.sh/your-64-char-random-topic
```

ntfy is also [self-hostable](https://docs.ntfy.sh/install/) — if you run your own instance, substitute your instance URL:

```bash
python3 check_dns.py example.com --ntfy-url https://ntfy.yourdomain.com/your-topic
```

The script works identically with both the public instance and self-hosted deployments.

### Testing ntfy independently

Before running the full script, verify your topic and device subscription are working with a direct curl test:

```bash
curl -d "Test message from check_dns" \
  -H "Title: DNS Checker Test" \
  -H "Priority: 3" \
  -H "Tags: warning" \
  https://ntfy.sh/your-topic
```

If the notification arrives in the app, your topic is correctly configured.

---

## State Tracking and Audit Logging

### State file

The state file (`check_dns_state.json` by default) persists the result of each delivery-critical check between runs. This is what enables regression detection — the script compares the current result against the saved state and identifies transitions.

The state file is created automatically on first run. On the first run there is no prior state, so a baseline is silently established with no notifications sent — you will not be alerted about pre-existing issues on day one.

Example state file:

```json
{
  "domain": "example.com",
  "last_run": "2026-03-20T07:13:43+00:00",
  "checks": {
    "dmarc": {
      "status": "ok",
      "consecutive_non_green": 0,
      "episode_started_from_green": false,
      "notified": false,
      "last_changed": "2026-03-20T07:13:43+00:00",
      "last_run": "2026-03-20T07:13:43+00:00"
    }
  }
}
```

The state file is scoped to a single domain. If you run the script against multiple domains, use a separate `--state-file` for each.

### Audit log

When `--audit-log` is specified, the script appends one JSON line per run recording the timestamp, domain, and status of every check:

```json
{"timestamp": "2026-03-20T07:13:02+00:00", "domain": "example.com", "results": {"mx": "ok", "spf": "ok", "dkim": "ok", "dmarc": "ok", "mta_sts": "ok", "bimi": "warn"}}
{"timestamp": "2026-03-20T07:13:43+00:00", "domain": "example.com", "results": {"mx": "ok", "spf": "ok", "dkim": "ok", "dmarc": "warn", "mta_sts": "ok", "bimi": "warn"}}
```

This gives you a timestamped history of your domain's posture over time. The file can be queried with `jq`:

```bash
# Show all runs where DMARC was not green
jq 'select(.results.dmarc != "ok")' check_dns_audit.jsonl

# Show the last 10 run timestamps and overall DMARC status
jq -r '[.timestamp, .results.dmarc] | @tsv' check_dns_audit.jsonl | tail -10
```

---

## Dead Man's Switch via healthchecks.io

The `--healthcheck-url` argument sends an unconditional HTTP GET to a [healthchecks.io](https://healthchecks.io)-compatible URL at the end of every successful run. This provides a dead man's switch — if the cron job stops executing for any reason (server down, Python error before the ping, etc.) healthchecks.io will alert you after the expected interval passes without a ping.

This is complementary to ntfy notifications: ntfy tells you when DNS configuration degrades, healthchecks.io tells you when the monitoring script itself has stopped running.

```bash
python3 check_dns.py example.com --healthcheck-url https://hc-ping.com/your-uuid
```

healthchecks.io has a generous free tier and is also [self-hostable](https://healthchecks.io/docs/self_hosted/).

---

## Automated Monitoring via Cron Job

A full production cron setup combines the HTML report, ntfy notifications, audit logging, and a healthchecks.io dead man's switch in a single command.

### Recommended cron entry

```
* * * * * sleep $((RANDOM % 60)) && /usr/bin/python3 /opt/dnstoolbox/check_dns.py example.com \
  --html \
  --ntfy-url https://ntfy.sh/your-64-char-random-topic \
  --audit-log /opt/dnstoolbox/check_dns_audit.jsonl \
  --healthcheck-url https://hc-ping.com/your-uuid \
  > /var/www/html/dns-report/index.html
```

The `sleep $((RANDOM % 60))` prefix adds a random offset of 0–59 seconds before each run. This avoids the cron job firing at exactly the same second every minute, which can cause thundering herd issues if multiple monitoring scripts run simultaneously.

The script exits cleanly with no interactive prompts when a domain is supplied as an argument, making it fully non-interactive and safe to run from cron.

The generated HTML report includes a timestamp in the header showing when it was last produced.

### Separate state and audit files per domain

If monitoring multiple domains, use explicit paths to keep state isolated:

```
* * * * * sleep $((RANDOM % 60)) && /usr/bin/python3 /opt/dnstoolbox/check_dns.py example.com \
  --html \
  --state-file /opt/dnstoolbox/state_example.com.json \
  --audit-log /opt/dnstoolbox/audit_example.com.jsonl \
  --ntfy-url https://ntfy.sh/your-topic \
  > /var/www/html/dns-report/example.com.html
```

---

## Check Detail

### MX Records

Queries the MX records for the domain. A missing result is flagged red — without MX records the domain cannot receive email and SPF/DMARC enforcement has no practical effect on inbound mail.

A null MX record (`0 .`) is a valid intentional configuration for domains not used for email (RFC 7505) and is treated as present.

### SPF (Sender Policy Framework)

Validates that a `v=spf1` TXT record exists and counts the number of DNS-lookup-consuming mechanisms (`include:`, `a`, `mx`, `ptr`, `exists:`, `redirect=`). RFC 7208 permits a maximum of 10 such lookups per evaluation. Exceeding this limit may cause receiving servers to discard the record entirely, meaning SPF checks pass vacuously and spoofed mail goes unchallenged.

If the lookup count is over 10, the result is amber with suggestions for SPF flattening.

### DKIM (DomainKeys Identified Mail)

Queries `<selector>._domainkey.<domain>` as a TXT record for each of the configured selectors. The default set tested is `default`, `selector1`, `selector2`.

**Important:** these are only common defaults. Most mail providers use a different selector entirely. If this check returns red, it does not necessarily mean DKIM is absent — your provider's selector may simply not be in the tested list. The label in the output always reflects the actual selectors being tested, so it will update automatically if you add more.

To find your actual selector, inspect the `DKIM-Signature:` header in a delivered email (available via "Show original" or "View source" in most mail clients) and look for the `s=` tag, for example `s=google` or `s=smtp`.

Once identified, add your selector to the `selectors` tuple in `check_dkim()`:

```python
def check_dkim(domain, selectors=('default', 'selector1', 'selector2', 'yourSelector')):
```

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

Queries `_dmarc.<domain>` and evaluates:

- **Policy (`p=`)** — `none` (monitoring only, red), `quarantine` (amber or green depending on alignment), `reject` (amber or green depending on alignment)
- **SPF alignment (`aspf=`)** — `r` relaxed (default, amber) or `s` strict (green)
- **DKIM alignment (`adkim=`)** — `r` relaxed (default, amber) or `s` strict (green)

The most secure posture is `p=reject; aspf=s; adkim=s`. Strict alignment prevents subdomain spoofing by requiring the envelope sender and DKIM signing domain to exactly match the `From:` header domain rather than merely sharing the same registered domain.

### MTA-STS (SMTP Mail Transfer Agent Strict Transport Security — RFC 8461)

MTA-STS allows a domain to declare that inbound SMTP connections must use TLS. This prevents downgrade attacks where a malicious actor intercepts SMTP traffic and negotiates an unencrypted connection.

The check validates:

1. A TXT record exists at `_mta-sts.<domain>`
2. A policy file is reachable at `https://mta-sts.<domain>/.well-known/mta-sts.txt` over HTTPS with a valid certificate
3. The policy file contains `version: STSv1`
4. `mode:` is `enforce` (green), `testing` (amber), or `none` (red)
5. `max_age:` is a valid positive integer within the RFC 8461 bounds (minimum 1 day recommended, maximum ~1 year)
6. Each `mx:` pattern in the policy file matches at least one of the domain's real DNS MX records — a mismatch in `enforce` mode is flagged red because it will cause sending MTAs to refuse delivery

Wildcard MX patterns (`*.example.com`) are supported and validated correctly — they match exactly one label as specified in RFC 8461 §3.1.

### BIMI (Brand Indicators for Message Identification)

BIMI allows a domain to display a logo in the email client's sender avatar slot. It requires a strong DMARC policy and a correctly formatted SVG logo. BIMI does not affect email deliverability and is **excluded from push notifications**.

The check validates:

**DNS record** — a TXT record at `default._bimi.<domain>` is present and contains a logo URL (`l=`).

**VMC (Verified Mark Certificate, `a=`)** — a VMC is issued by a Certificate Authority (currently DigiCert) and cryptographically links your logo to your domain. Gmail and Apple Mail require a VMC before they will display the logo. Yahoo Mail and Fastmail support self-asserted BIMI without a VMC. The absence of a VMC is flagged amber rather than red — the configuration is valid for a subset of providers.

**Logo reachability** — the SVG file at the `l=` URL is fetched and must return HTTP 200.

**SVG Tiny P/S validation** — the BIMI specification requires logos to conform to the SVG Tiny Portable/Secure (P/S) profile, a restricted subset of SVG Tiny 1.2 designed to be safe for display in email clients. The following are checked:

| Requirement | Detail |
|---|---|
| `version="1.2"` | Must be exactly `1.2` |
| `baseProfile="tiny-ps"` | Must be exactly `tiny-ps` |
| Square `viewBox` | Width and height must be equal (1:1 aspect ratio) |
| `preserveAspectRatio="xMidYMid meet"` | Recommended for consistent centring |
| `<title>` element | Must be present (brand/company name) |
| No `x=` or `y=` on root element | Common Adobe Illustrator export artefact; must be removed |
| No `<script>` elements | Prohibited |
| No JS event handlers | `onclick`, `onload`, etc. are prohibited |
| No animation elements | `<animate>`, `<animateMotion>`, `<animateTransform>`, `<set>` are prohibited |
| No `<foreignObject>` | Prohibited |
| No external URL references | `href`/`src` pointing to external resources are prohibited |
| No embedded raster images | Base64 PNG/JPEG data URIs are prohibited; logos must be fully vector |
| File size ≤ 32 KB | Recommended maximum; some validators enforce this strictly |
| `Content-Type: image/svg+xml` | Expected MIME type from the web server |

Hard failures (items that will prevent BIMI from functioning) are flagged red. Items that may cause display inconsistencies or are not strictly required are flagged amber.

---

## DNS Caching

The script creates a module-level DNS resolver with in-process caching explicitly disabled. Every query goes directly to the wire, ensuring results always reflect the current live state of your DNS records. This is particularly important when testing DNS changes with short TTLs.

If you want to confirm what a specific upstream resolver currently holds for a record independently of the script, query it directly:

```bash
dig TXT _dmarc.example.com @1.1.1.1
```

---

## Limitations

- DKIM selector detection only tests the selectors defined in `check_dkim()`. If your provider uses a different selector the check will return red even if DKIM is correctly configured. See the DKIM section above for how to identify and add your selector.
- HTTP requests use a 5-second timeout. Slow or firewalled endpoints may be reported as unreachable.
- DMARC `pct=` (percentage) and `fo=` (failure options) tags are not evaluated.
- MTA-STS SMTP TLS reporting (`_smtp._tls.<domain>`) is not checked.
- The state file tracks one domain per file. Use `--state-file` to specify separate files when monitoring multiple domains.

---

## References

- [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) — Sender Policy Framework (SPF)
- [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) — DomainKeys Identified Mail (DKIM)
- [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) — Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461) — SMTP MTA Strict Transport Security (MTA-STS)
- [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505) — A "Null MX" No Delivery Resource Record
- [BIMI Working Group](https://bimigroup.org/) — BIMI specification and SVG logo requirements
- [ntfy](https://ntfy.sh) — Push notification service used for alerting
- [healthchecks.io](https://healthchecks.io) — Dead man's switch for cron job monitoring

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

---

## License

This project is open source and available under the MIT License.
