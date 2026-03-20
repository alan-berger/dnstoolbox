# DNS Email Security Checker

A Python command-line tool that performs comprehensive validation of email-related DNS records and security policies. Results are presented with a traffic light system — green, amber, red — each accompanied by a plain-English explanation of the result and, where applicable, actionable suggestions for remediation.

The tool can output directly to the terminal or produce a self-contained HTML report suitable for hosting on a website, making it well suited to automated monitoring via a cron job.

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

No other third-party dependencies are required. The HTML report is generated using Python's standard library only.

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

## Automated Monitoring via Cron Job

The HTML report mode is designed to integrate cleanly with a cron job for ongoing monitoring. A typical setup writes the report to a directory served by your web server, giving you an always-current view of your domain's email security posture.

### Example: update the report every 6 hours

```bash
crontab -e
```

Add a line such as:

```
0 */6 * * * /usr/bin/python3 /opt/dnstoolbox/check_dns.py example.com --html > /var/www/html/dns-report/index.html
```

Adjust the Python path, script path, domain, and output path to match your environment. The script exits cleanly with no interactive prompts when a domain is supplied as an argument, making it fully non-interactive.

If running inside a virtual environment:

```
0 */6 * * * /opt/dnstoolbox/venv/bin/python3 /opt/dnstoolbox/check_dns.py example.com --html > /var/www/html/dns-report/index.html
```

The generated report includes a timestamp showing when it was last run, displayed in the report header.

---

## Check Detail

### MX Records

Queries the MX records for the domain. A missing result is flagged red — without MX records the domain cannot receive email and SPF/DMARC enforcement has no practical effect on inbound mail.

A null MX record (`0 .`) is a valid intentional configuration for domains not used for email (RFC 7505) and is treated as present.

### SPF (Sender Policy Framework)

Validates that a `v=spf1` TXT record exists and counts the number of DNS-lookup-consuming mechanisms (`include:`, `a`, `mx`, `ptr`, `exists:`, `redirect=`). RFC 7208 permits a maximum of 10 such lookups per evaluation. Exceeding this limit may cause receiving servers to discard the record entirely, meaning SPF checks pass vacuously and spoofed mail goes unchallenged.

If the lookup count is over 10, the result is amber with suggestions for SPF flattening.

### DKIM (DomainKeys Identified Mail)

Queries `<selector>._domainkey.<domain>` as a TXT record for each of the following selectors: `default`, `selector1`, `selector2`.

**Important:** these are only common defaults. Most mail providers use a different selector entirely. If this check returns red, it does not necessarily mean DKIM is absent — your provider's selector may simply not be in the tested list.

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

BIMI allows a domain to display a logo in the email client's sender avatar slot. It requires a strong DMARC policy and a correctly formatted SVG logo.

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

## Limitations

- DKIM selector detection is limited to `default`, `selector1`, and `selector2`. If your provider uses a different selector the check will return red even if DKIM is correctly configured. See the DKIM section above for how to identify and add your selector.
- DNS queries use the system resolver. Results may differ from what an external resolver returns if split-horizon DNS is in use.
- HTTP requests use a 5-second timeout. Slow or firewalled endpoints may be reported as unreachable.
- DMARC `pct=` (percentage) and `fo=` (failure options) tags are not evaluated.
- MTA-STS SMTP TLS reporting (`_smtp._tls.<domain>`) is not checked.

---

## References

- [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) — Sender Policy Framework (SPF)
- [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) — DomainKeys Identified Mail (DKIM)
- [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) — Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461) — SMTP MTA Strict Transport Security (MTA-STS)
- [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505) — A "Null MX" No Delivery Resource Record
- [BIMI Working Group](https://bimigroup.org/) — BIMI specification and SVG logo requirements

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

---

## License

This project is open source and available under the MIT License.
