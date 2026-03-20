#!/usr/bin/env python3
import argparse
import html as html_lib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import requests

# ---------------------------------------------------------------------------
# ANSI colours (terminal)
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"   # used exclusively for suggestion lines
RESET  = "\033[0m"

_STATUS_ANSI    = {'ok': GREEN, 'warn': YELLOW, 'missing': RED}
_STATUS_SYMBOL  = {'ok': '✓',   'warn': '⚠',   'missing': '✗'}
_STATUS_LABEL   = {'ok': 'PASS', 'warn': 'WARNING', 'missing': 'FAIL'}
_STATUS_COLOUR  = {'ok': 'green', 'warn': 'amber', 'missing': 'red'}

# ---------------------------------------------------------------------------
# HTML colour palette
# ---------------------------------------------------------------------------
_HTML_TEXT       = {'ok': '#14532d', 'warn': '#78350f', 'missing': '#7f1d1d'}
_HTML_BORDER     = {'ok': '#16a34a', 'warn': '#d97706', 'missing': '#dc2626'}
_HTML_BG         = {'ok': '#f0fdf4', 'warn': '#fffbeb', 'missing': '#fef2f2'}
_HTML_BADGE_BG   = {'ok': '#dcfce7', 'warn': '#fef3c7', 'missing': '#fee2e2'}
_HTML_BADGE_TEXT = {'ok': '#15803d', 'warn': '#b45309', 'missing': '#b91c1c'}

# ---------------------------------------------------------------------------
# Delivery-critical checks — the only ones tracked for state changes and
# notifications. BIMI is intentionally excluded as it does not affect
# email deliverability.
# ---------------------------------------------------------------------------
DELIVERY_CRITICAL_KEYS = {'mx', 'spf', 'dkim', 'dmarc', 'mta_sts'}

# ntfy priority integers (1=min … 5=max) and emoji tags per status
_NTFY_PRIORITY = {'warn': '3', 'missing': '4', 'ok': '2'}
_NTFY_TAGS     = {'warn': 'warning', 'missing': 'rotating_light', 'ok': 'white_check_mark'}

# ---------------------------------------------------------------------------
# Shared HTTP helpers
# ---------------------------------------------------------------------------
_HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "*/*",
}


# Module-level resolver with caching explicitly disabled.
# dnspython's default resolver maintains an in-process cache that respects
# TTL but could serve stale results if the same record is queried more than
# once within a single run. Disabling it guarantees every query goes to the
# wire, which is important when testing DNS changes with short TTLs.
_resolver = dns.resolver.Resolver()
_resolver.cache = None


def get_dns_records(domain, record_type):
    try:
        answers = _resolver.resolve(domain, record_type)
        return [rdata.to_text().strip('"') for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []


def fetch_url(url):
    """Returns (status_code, body) or (None, error_str)."""
    try:
        r = requests.get(url, headers=_HTTP_HEADERS, timeout=5, allow_redirects=True)
        return r.status_code, r.text
    except requests.RequestException as e:
        return None, str(e)


def fetch_url_full(url):
    """Returns (status_code, headers_dict, body) or (None, {}, error_str)."""
    try:
        r = requests.get(url, headers=_HTTP_HEADERS, timeout=5, allow_redirects=True)
        return r.status_code, dict(r.headers), r.text
    except requests.RequestException as e:
        return None, {}, str(e)


# ---------------------------------------------------------------------------
# Checks
#
# Every function returns a 4-tuple:
#   records     : list[str]  — raw technical detail lines
#   status      : str        — 'ok' | 'warn' | 'missing'
#   summary     : str        — one sentence explaining the overall result
#   suggestions : list[str]  — actionable fix steps; empty list when status == 'ok'
# ---------------------------------------------------------------------------

def check_mx(domain):
    mx_records = get_dns_records(domain, 'MX')
    if mx_records:
        return (
            mx_records,
            "ok",
            "MX records are present. This domain can receive email.",
            [],
        )
    return (
        ["No MX records found"],
        "missing",
        "No MX records found. Without MX records this domain cannot receive email "
        "and SPF/DMARC have no meaningful effect on inbound mail.",
        [
            "Add at least one MX record to your DNS zone, e.g.: "
            "yourdomain.com. IN MX 10 mail.yourdomain.com.",
            "If this domain is intentionally not used for email, add a null MX record "
            "(RFC 7505): yourdomain.com. IN MX 0 . — this explicitly signals no mail is accepted.",
            "Verify after publishing with: dig MX yourdomain.com",
        ],
    )


def check_spf(domain):
    txt_records = get_dns_records(domain, 'TXT')
    spf_records = [r for r in txt_records if r.startswith('v=spf1')]
    if not spf_records:
        return (
            ["No SPF record found"],
            "missing",
            "No SPF record found. Any mail server can send email claiming to be "
            "from this domain without being rejected by SPF.",
            [
                "Create a DNS TXT record at your domain root containing your SPF policy. "
                "A typical starting point: v=spf1 include:_spf.yourprovider.com ~all",
                "Replace the include: value with the mechanism your mail provider "
                "specifies in their DNS/SPF documentation.",
                "Use ~all (softfail) while testing, then tighten to -all (hardfail) "
                "once you are confident all legitimate sending sources are covered.",
                "Verify publication with: dig TXT yourdomain.com | grep spf",
            ],
        )

    spf = spf_records[0]
    # RFC 7208 §4.6.4 — mechanisms that consume a DNS lookup
    lookup_count = len(re.findall(r'(include:|a\b|mx\b|ptr\b|exists:|redirect=)', spf))
    records = [spf, f"DNS Lookups: {lookup_count}/10"]

    if lookup_count > 10:
        return (
            records,
            "warn",
            f"SPF record has {lookup_count} DNS lookups, exceeding the RFC 7208 limit "
            "of 10. Receiving servers may discard the record entirely, allowing spoofed "
            "mail to pass SPF checks.",
            [
                "Use an SPF flattening tool (e.g. dmarcian SPF Surveyor, mxtoolbox) to "
                "resolve include: chains into direct IP ranges, reducing lookup count.",
                "Remove redundant mechanisms — if both 'a' and 'mx' resolve to the same "
                "IP address, one can be dropped.",
                "Check whether any include: targets themselves have deep lookup chains "
                "that contribute to the total count.",
                "After flattening, keep your SPF record updated if your provider "
                "changes their IP ranges, as flattened records do not update automatically.",
            ],
        )

    return (
        records,
        "ok",
        f"SPF record is valid with {lookup_count} DNS lookup(s) "
        "(limit is 10, RFC 7208). Authorised senders are correctly defined.",
        [],
    )


def check_dkim(domain, selectors=('default', 'selector1', 'selector2')):
    all_records = []
    for selector in selectors:
        dkim_records = get_dns_records(f"{selector}._domainkey.{domain}", 'TXT')
        for rec in dkim_records:
            all_records.append(f"{selector}: {rec}")

    if not all_records:
        selector_list = ", ".join(selectors)
        return (
            [f"No DKIM record found for selectors: {selector_list}"],
            "missing",
            f"No DKIM record found for the tested selectors ({selector_list}). "
            "Without DKIM, email cannot be cryptographically verified and DMARC "
            "alignment on DKIM will always fail.",
            [
                "This script only tests the selectors listed above. Your mail provider "
                "almost certainly uses a different one — a missing result here does "
                "not necessarily mean DKIM is absent.",
                "To find your actual selector: inspect the DKIM-Signature: header in "
                "a delivered email (viewable via 'Show original' or 'View source' in "
                "most mail clients) and look for the s= tag, e.g. s=google or s=smtp.",
                "Once you know your selector, edit this script and add it to the "
                "selectors tuple in check_dkim(), then re-run.",
                "If DKIM is genuinely not configured: generate an RSA-2048 or Ed25519 "
                "key pair, publish the public key as a TXT record at "
                "<selector>._domainkey.yourdomain.com, then configure your mail server "
                "or provider to sign outbound mail with the private key.",
                "Verify a known selector with: "
                "dig TXT <selector>._domainkey.yourdomain.com",
            ],
        )

    return (
        all_records,
        "ok",
        "DKIM signing key found. Outbound mail can be cryptographically signed, "
        "allowing receivers to verify it was not tampered with in transit.",
        [],
    )


def check_dmarc(domain):
    dmarc_records = get_dns_records(f"_dmarc.{domain}", 'TXT')
    if not dmarc_records:
        return (
            ["No DMARC record found"],
            "missing",
            "No DMARC record found. Without DMARC, SPF and DKIM results cannot be "
            "used to protect against direct domain spoofing.",
            [
                "Start with a monitoring-only record to observe traffic without "
                "affecting delivery: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                "The rua= address will receive aggregate XML reports from receiving "
                "mail servers — review these to understand your mail flows before enforcing.",
                "Publish as a TXT record at _dmarc.yourdomain.com (note the leading underscore).",
                "Escalation path once reports look clean: p=none -> p=quarantine -> p=reject. "
                "Spend at least a few weeks at each stage.",
                "Verify publication with: dig TXT _dmarc.yourdomain.com",
            ],
        )

    record_str = " ".join(dmarc_records).lower()

    policy = None
    if "p=" in record_str:
        policy = record_str.split("p=")[1].split(";")[0].strip()

    aspf  = record_str.split("aspf=")[1].split(";")[0].strip()  if "aspf="  in record_str else "r"
    adkim = record_str.split("adkim=")[1].split(";")[0].strip() if "adkim=" in record_str else "r"

    status_msg = (
        f"Policy={policy.upper() if policy else 'MISSING'}, "
        f"ASPF={aspf.upper()}, ADKIM={adkim.upper()}"
    )
    records = dmarc_records + [status_msg]

    if not policy or policy == "none":
        return (
            records,
            "missing",
            "DMARC policy is 'none' — monitoring mode only. Unauthenticated or "
            "spoofed mail will still be delivered to recipients.",
            [
                "Review your DMARC aggregate reports (sent to the rua= address) to "
                "identify all legitimate mail flows before enforcing.",
                "Change p=none to p=quarantine as the next step — this routes "
                "suspicious mail to the recipient's spam folder rather than the inbox.",
                "Once p=quarantine has been in place for several weeks without "
                "flagging legitimate mail, move to p=reject for full enforcement.",
                "If you have no rua= address set, add one — you cannot safely "
                "enforce without first seeing your traffic data.",
            ],
        )

    if policy in ("quarantine", "reject"):
        action = "rejected outright" if policy == "reject" else "sent to quarantine"
        if aspf == "s" and adkim == "s":
            return (
                records,
                "ok",
                f"Strong DMARC enforcement (p={policy}) with strict SPF and DKIM "
                f"alignment. Spoofed or unauthenticated mail is {action}. "
                "This is the most secure posture.",
                [],
            )

        missing_flags = " and ".join(
            t for t, v in [("aspf=s", aspf), ("adkim=s", adkim)] if v != "s"
        )
        return (
            records,
            "warn",
            f"DMARC is enforced (p={policy}) but alignment is relaxed. "
            f"Adding {missing_flags} would prevent subdomain spoofing and "
            "provide the strongest protection.",
            [
                f"Add {missing_flags} to your DMARC record to require exact domain "
                "matching rather than organisational-domain matching.",
                "aspf=s requires the envelope sender (Return-Path) domain to exactly "
                "match the From: header domain — not just share the same registered domain.",
                "adkim=s requires the DKIM d= tag to exactly match the From: header "
                "domain. Ensure your signing configuration uses the correct domain.",
                "Before enabling strict alignment, confirm that all legitimate mail "
                "passes strict checks — use DMARC reports to verify there are no failures.",
            ],
        )

    return (
        records,
        "warn",
        f"DMARC policy value '{policy}' is not recognised. "
        "Expected: none, quarantine, or reject.",
        [
            f"Check your DMARC record for a typo in the p= tag (found: '{policy}'). "
            "Valid values are: none, quarantine, reject.",
            "Retrieve your current record with: dig TXT _dmarc.yourdomain.com",
        ],
    )


# ---------------------------------------------------------------------------
# MTA-STS (RFC 8461)
# ---------------------------------------------------------------------------

def _parse_mta_sts_policy(text):
    """Parse an mta-sts.txt policy file into a dict; mx key holds a list."""
    policy = {}
    for line in text.strip().splitlines():
        line = line.strip()
        if ':' in line:
            key, _, value = line.partition(':')
            key, value = key.strip().lower(), value.strip()
            if key == 'mx':
                policy.setdefault('mx', []).append(value)
            else:
                policy[key] = value
    return policy


def _mx_matches_pattern(mx_host, pattern):
    """
    Match an MX hostname against an MTA-STS policy pattern.
    Wildcards (*.) match exactly one label (RFC 8461 §3.1).
    """
    mx_host = mx_host.rstrip('.').lower()
    pattern  = pattern.rstrip('.').lower()
    if pattern.startswith('*.'):
        suffix = pattern[2:]
        if mx_host.endswith('.' + suffix):
            prefix = mx_host[:-(len(suffix) + 1)]
            return '.' not in prefix
        return False
    return mx_host == pattern


_MTA_STS_SETUP_HINTS = [
    "Create a TXT record at _mta-sts.yourdomain.com with value: "
    "v=STSv1; id=<timestamp> (e.g. id=20240101000000). "
    "Update the id= value whenever you change the policy file.",
    "Host a policy file at https://mta-sts.yourdomain.com/.well-known/mta-sts.txt "
    "served over HTTPS with a valid, trusted TLS certificate.",
    "Minimal policy file contents:\n"
    "    version: STSv1\n"
    "    mode: testing\n"
    "    mx: mail.yourdomain.com\n"
    "    max_age: 86400",
    "Start with mode: testing to observe without enforcing, then switch to "
    "mode: enforce once you have confirmed TLS is working correctly.",
]

_MTA_STS_FILE_HINTS = [
    "Ensure mta-sts.yourdomain.com is a valid DNS A or CNAME record pointing "
    "to a web server.",
    "The web server must serve HTTPS with a publicly trusted TLS certificate — "
    "self-signed certificates will not be accepted by sending MTAs.",
    "Verify the path /.well-known/mta-sts.txt is accessible: "
    "curl -I https://mta-sts.yourdomain.com/.well-known/mta-sts.txt",
    "Check your web server config — some servers require explicit MIME type "
    "configuration for .txt files under .well-known/.",
]


def check_mta_sts(domain):
    dns_records = get_dns_records(f"_mta-sts.{domain}", 'TXT')
    if not dns_records:
        return (
            [f"No MTA-STS DNS TXT record found at _mta-sts.{domain}"],
            "missing",
            "MTA-STS is not configured. Inbound SMTP connections are not required "
            "to use TLS, leaving mail vulnerable to downgrade attacks.",
            _MTA_STS_SETUP_HINTS,
        )

    results = list(dns_records)
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    status_code, body = fetch_url(url)

    if status_code is None:
        results.append(f"Error fetching policy file at {url}: {body}")
        return (
            results,
            "missing",
            "MTA-STS DNS record exists but the policy file could not be fetched. "
            "The policy will not be applied until the file is accessible over HTTPS.",
            _MTA_STS_FILE_HINTS,
        )
    if status_code != 200:
        results.append(f"Policy file inaccessible at {url} (HTTP {status_code})")
        return (
            results,
            "missing",
            f"MTA-STS DNS record exists but the policy file returned HTTP {status_code}. "
            "The policy cannot be applied until the file is publicly accessible.",
            _MTA_STS_FILE_HINTS,
        )

    policy      = _parse_mta_sts_policy(body)
    hard_errs   = []
    warnings    = []
    suggestions = []

    # version
    if policy.get('version', '').lower() != 'stsv1':
        hard_errs.append(
            f"Invalid version field: '{policy.get('version', 'missing')}' "
            "(must be STSv1 per RFC 8461)"
        )
        suggestions.append("Set the first line of your policy file to: version: STSv1")

    # mode
    mode = policy.get('mode', '').lower()
    if mode == 'enforce':
        results.append(
            "Mode: enforce — sending MTAs must establish valid TLS or the "
            "message is rejected"
        )
    elif mode == 'testing':
        warnings.append(
            "Mode: testing — policy is not enforced; failures are reported "
            "but connections are not rejected"
        )
        suggestions.append(
            "Once you have verified that all inbound mail flows use valid TLS, "
            "change mode: testing to mode: enforce and update the id= value in "
            "your DNS TXT record."
        )
    elif mode == 'none':
        hard_errs.append(
            "Mode: none — policy is explicitly disabled; no TLS enforcement is applied"
        )
        suggestions.append(
            "Change mode: none to mode: testing or mode: enforce in your policy file, "
            "then update the id= value in the _mta-sts. DNS TXT record."
        )
    else:
        hard_errs.append(
            f"Mode: unrecognised value '{mode}' (expected: enforce, testing, or none)"
        )
        suggestions.append(
            f"Fix the mode field in your policy file. Found '{mode}'; "
            "valid values are: enforce, testing, none."
        )

    # max_age
    RFC_MAX_AGE = 31557600
    try:
        max_age = int(policy.get('max_age', 0))
        if max_age <= 0:
            hard_errs.append(
                "max_age is missing or zero — a valid positive integer is required (RFC 8461)"
            )
            suggestions.append(
                "Add a max_age field to your policy file, e.g.: max_age: 86400 "
                "(1 day). A value of 604800 (7 days) or 2592000 (30 days) is "
                "typical for production."
            )
        elif max_age < 86400:
            warnings.append(
                f"max_age: {max_age}s is very short (under 1 day). A short max_age "
                "weakens the caching guarantee; RFC 8461 recommends at least 86400s"
            )
            suggestions.append(
                f"Increase max_age from {max_age} to at least 86400 (1 day). "
                "A longer value such as 604800 (7 days) or 2592000 (30 days) "
                "provides stronger protection."
            )
        elif max_age > RFC_MAX_AGE:
            warnings.append(
                f"max_age: {max_age}s exceeds the RFC 8461 maximum of "
                f"{RFC_MAX_AGE}s (~1 year)"
            )
            suggestions.append(
                f"Reduce max_age to no more than {RFC_MAX_AGE} seconds (~1 year) "
                "to comply with RFC 8461."
            )
        else:
            results.append(
                f"max_age: {max_age}s — receiving MTAs will cache this policy for "
                f"{max_age // 86400} day(s)"
            )
    except (ValueError, TypeError):
        hard_errs.append(
            f"max_age: invalid non-integer value '{policy.get('max_age')}'"
        )
        suggestions.append(
            "Ensure max_age is a plain integer (number of seconds), "
            f"e.g.: max_age: 86400 — found: '{policy.get('max_age')}'"
        )

    # MX alignment
    policy_mx = policy.get('mx', [])
    if not policy_mx:
        hard_errs.append(
            "No MX entries in policy file — at least one mx: line is required "
            "(RFC 8461 §3.1)"
        )
        suggestions.append(
            "Add one mx: line for each MX hostname in your DNS zone, e.g.: "
            "mx: mail.yourdomain.com. "
            "Wildcard patterns are allowed: mx: *.yourdomain.com "
            "(matches exactly one label)."
        )
    else:
        actual_mx    = get_dns_records(domain, 'MX')
        actual_hosts = [
            parts[1].rstrip('.').lower()
            for mx in actual_mx
            for parts in [mx.split()]
            if len(parts) >= 2
        ]
        mx_mismatch = False
        for pattern in policy_mx:
            matched = any(_mx_matches_pattern(h, pattern) for h in actual_hosts)
            if matched:
                results.append(f"MX pattern '{pattern}': matches DNS MX record \u2713")
            else:
                results.append(f"MX pattern '{pattern}': no matching DNS MX record \u2717")
                mx_mismatch = True

        if mx_mismatch:
            if mode == 'enforce':
                hard_errs.append(
                    "MX mismatch in enforce mode — sending MTAs will reject connections "
                    "to your mail server, causing legitimate mail delivery to fail"
                )
            else:
                warnings.append(
                    "MX mismatch detected — this would cause delivery failures "
                    "if mode were changed to enforce"
                )
            suggestions.append(
                "Compare the mx: lines in your policy file against your DNS MX "
                "records: dig MX yourdomain.com"
            )
            suggestions.append(
                "Update the mx: entries in your policy file to match your current "
                "MX hostnames exactly, then increment the id= value in your "
                "_mta-sts. DNS TXT record to invalidate cached copies."
            )
            suggestions.append(
                "Note: wildcard patterns (*.example.com) match exactly one label — "
                "mail.example.com matches, but smtp.mail.example.com does not."
            )

    results.extend(warnings)
    results.extend(hard_errs)

    if hard_errs:
        return (
            results,
            "missing",
            "MTA-STS policy has critical configuration errors and cannot be "
            "correctly applied. See details and suggestions below.",
            suggestions,
        )
    if warnings:
        return (
            results,
            "warn",
            "MTA-STS is configured but has warnings that may reduce security "
            "or cause delivery issues. Review the suggestions below.",
            suggestions,
        )
    return (
        results,
        "ok",
        "MTA-STS policy is active in enforce mode with correct MX alignment. "
        "Sending mail servers must use valid TLS when delivering to this domain.",
        [],
    )


# ---------------------------------------------------------------------------
# BIMI (BIMI Working Group spec / SVG Tiny P/S profile)
# ---------------------------------------------------------------------------

def _validate_bimi_svg(svg_text, content_type=""):
    """
    Validate SVG against the BIMI SVG Tiny Portable/Secure (P/S) profile.
    Returns (issues, warnings, svg_suggestions).
    """
    issues          = []
    warnings        = []
    svg_suggestions = []

    if content_type and 'image/svg+xml' not in content_type.lower():
        warnings.append(
            f"Unexpected Content-Type '{content_type}' "
            "(BIMI expects image/svg+xml)"
        )
        svg_suggestions.append(
            "Configure your web server to serve the SVG file with "
            "Content-Type: image/svg+xml"
        )

    size_bytes = len(svg_text.encode('utf-8'))
    if size_bytes > 32768:
        warnings.append(
            f"File size {size_bytes:,} bytes exceeds the recommended 32 KB BIMI limit"
        )
        svg_suggestions.append(
            f"Reduce the SVG file size (currently {size_bytes:,} bytes, limit is 32,768). "
            "Use a tool like SVGO to remove redundant metadata, simplify paths, "
            "and reduce node counts."
        )

    try:
        root = ET.fromstring(svg_text)
    except ET.ParseError as e:
        return [f"SVG is not valid XML: {e}"], warnings, [
            "Fix the XML syntax error in the SVG file. Open it in a text editor "
            "and check for unclosed tags, invalid characters, or malformed attributes."
        ]

    SVG_NS = "http://www.w3.org/2000/svg"

    if root.tag not in (f"{{{SVG_NS}}}svg", "svg"):
        issues.append(f"Root element is not <svg> (found: {root.tag})")
        return issues, warnings, ["The file root element must be <svg>. Ensure this is a valid SVG file."]

    if not root.tag.startswith(f"{{{SVG_NS}}}"):
        declared = root.get('xmlns', '')
        if declared != SVG_NS:
            issues.append(
                f"SVG namespace incorrect or missing "
                f"(expected xmlns=\"{SVG_NS}\", found \"{declared}\")"
            )
            svg_suggestions.append(f'Add xmlns="{SVG_NS}" to the root <svg> element.')

    version = root.get('version', '')
    if version != '1.2':
        issues.append(f"version must be '1.2' for SVG Tiny P/S (found: '{version}')")
        svg_suggestions.append(
            f'Set version="1.2" on the root <svg> element '
            f'(currently: "{version}" or missing). '
            "This is a hard requirement of the BIMI SVG Tiny P/S profile."
        )

    base_profile = root.get('baseProfile', '')
    if base_profile.lower() != 'tiny-ps':
        issues.append(f"baseProfile must be 'tiny-ps' (found: '{base_profile}')")
        svg_suggestions.append(
            f'Set baseProfile="tiny-ps" on the root <svg> element '
            f'(currently: "{base_profile}" or missing). '
            "If exporting from Adobe Illustrator, change 'tiny' to 'tiny-ps' "
            "manually in a text editor after export."
        )

    if root.get('x') is not None or root.get('y') is not None:
        warnings.append("Root <svg> element has x= or y= attributes (invalid in Tiny P/S)")
        svg_suggestions.append(
            "Remove the x= and y= attributes from the root <svg> tag. "
            "These are added automatically by Adobe Illustrator on SVG Tiny 1.2 "
            "export and must be deleted manually."
        )

    viewbox = root.get('viewBox', '')
    if not viewbox:
        issues.append("viewBox attribute is required but is missing")
        svg_suggestions.append(
            "Add a viewBox attribute to the root <svg> element, e.g.: "
            'viewBox="0 0 100 100". The dimensions must be square (equal width and height).'
        )
    else:
        parts = viewbox.split()
        if len(parts) == 4:
            try:
                w, h = float(parts[2]), float(parts[3])
                if abs(w - h) > 0.01:
                    warnings.append(
                        f"viewBox is not square ({w:.4g} x {h:.4g}); "
                        "BIMI logos must have a 1:1 aspect ratio"
                    )
                    svg_suggestions.append(
                        f"Adjust the viewBox so width and height are equal "
                        f"(currently {w:.4g} x {h:.4g}). Either add padding to "
                        "your design to fit a square canvas, or adjust the fourth "
                        "viewBox value to match the third."
                    )
            except ValueError:
                warnings.append(f"Could not parse viewBox dimensions: '{viewbox}'")

    par = root.get('preserveAspectRatio', '')
    if not par:
        warnings.append("preserveAspectRatio is not set")
        svg_suggestions.append(
            'Add preserveAspectRatio="xMidYMid meet" to the root <svg> element. '
            "This ensures the logo is centred correctly in the circular or square "
            "avatar slots used by email clients."
        )
    elif par != 'xMidYMid meet':
        warnings.append(f"preserveAspectRatio is '{par}' (BIMI recommends 'xMidYMid meet')")
        svg_suggestions.append(
            f'Change preserveAspectRatio="{par}" to preserveAspectRatio="xMidYMid meet".'
        )

    title_tag_ns = f"{{{SVG_NS}}}title"
    has_title = any(child.tag in (title_tag_ns, "title") for child in root)
    if not has_title:
        warnings.append("<title> element is missing")
        svg_suggestions.append(
            "Add a <title> element as the first child of the root <svg> element "
            "containing your brand or company name, e.g.: <title>Acme Corp</title>. "
            "This is required by the BIMI specification."
        )

    if re.search(r'<\s*script', svg_text, re.IGNORECASE):
        issues.append("<script> elements are prohibited in SVG Tiny P/S")
        svg_suggestions.append(
            "Remove all <script> tags from the SVG file. Open in a text editor "
            "and delete any <script>...</script> blocks."
        )

    if re.compile(r'\bon\w+\s*=', re.IGNORECASE).search(svg_text):
        issues.append(
            "JavaScript event-handler attributes (onclick, onload, etc.) "
            "are prohibited in SVG Tiny P/S"
        )
        svg_suggestions.append(
            "Remove all inline event-handler attributes (onclick, onload, "
            "onmouseover, etc.) from the SVG. Search the file for 'on' followed "
            "by an equals sign."
        )

    if re.compile(
        r'<\s*(?:animate|animateMotion|animateTransform|set)\b', re.IGNORECASE
    ).search(svg_text):
        issues.append("Animation elements are prohibited in SVG Tiny P/S")
        svg_suggestions.append(
            "Remove all animation elements: <animate>, <animateMotion>, "
            "<animateTransform>, and <set>. These are sometimes added by design "
            "tools and must be deleted manually."
        )

    if re.search(r'<\s*foreignObject', svg_text, re.IGNORECASE):
        issues.append("<foreignObject> is prohibited in SVG Tiny P/S")
        svg_suggestions.append("Remove all <foreignObject> elements from the SVG file.")

    if re.compile(
        r'(?:href|src|xlink:href)\s*=\s*["\']https?://', re.IGNORECASE
    ).search(svg_text):
        issues.append(
            "External resource references (http/https URLs) are prohibited "
            "in SVG Tiny P/S"
        )
        svg_suggestions.append(
            "Remove all external URL references from href, src, and xlink:href "
            "attributes. All resources must be self-contained within the SVG file. "
            "Inline any fonts or images as paths or data URIs (non-raster only)."
        )

    if re.compile(
        r'data\s*:\s*(?:image|img)/(?:png|jpe?g|gif|webp|bmp)', re.IGNORECASE
    ).search(svg_text):
        issues.append(
            "Embedded raster image (data URI) detected — BIMI SVGs must be "
            "fully vector-based"
        )
        svg_suggestions.append(
            "Remove embedded raster images (PNG/JPEG data URIs). Re-create any "
            "bitmap elements as vector paths in your design tool. Raster images "
            "cannot be converted to vector simply by changing the file extension — "
            "they must be manually traced or redrawn as vector artwork."
        )

    return issues, warnings, svg_suggestions


def check_bimi(domain):
    bimi_records = get_dns_records(f"default._bimi.{domain}", 'TXT')

    if not bimi_records:
        return (
            [f"No BIMI DNS TXT record found at default._bimi.{domain}"],
            "missing",
            "BIMI is not configured for this domain. No logo will display "
            "in email clients.",
            [
                "Create a DNS TXT record at default._bimi.yourdomain.com with a "
                "value referencing your SVG logo, e.g.: "
                "v=BIMI1; l=https://yourdomain.com/bimi/logo.svg",
                "The SVG must conform to the BIMI SVG Tiny P/S profile — see "
                "https://bimigroup.org/creating-bimi-svg-logo-files/ for details.",
                "Your domain must also have a DMARC policy of p=quarantine or "
                "p=reject before BIMI will display in supporting email clients.",
                "Without a Verified Mark Certificate (VMC), the logo will only "
                "display in providers that support self-asserted BIMI (e.g. Yahoo, "
                "Fastmail). Gmail and Apple Mail require a VMC.",
            ],
        )

    results  = list(bimi_records)
    logo_url = None
    vmc_url  = None
    suggestions = []

    for rec in bimi_records:
        for part in rec.split(';'):
            part = part.strip()
            if part.lower().startswith('l='):
                logo_url = part[2:].strip()
            elif part.lower().startswith('a='):
                vmc_url = part[2:].strip()

    overall = "ok"

    if vmc_url:
        vmc_code, _ = fetch_url(vmc_url)
        if vmc_code == 200:
            results.append(
                f"VMC certificate accessible at {vmc_url} — "
                "Gmail and Apple Mail will display this logo"
            )
        elif vmc_code is not None:
            results.append(
                f"VMC certificate URL returned HTTP {vmc_code} — "
                "logo will not display in Gmail or Apple Mail until the "
                "VMC file is accessible"
            )
            overall = "warn"
            suggestions.append(
                f"The VMC file at {vmc_url} returned HTTP {vmc_code}. "
                "Ensure the .pem file is publicly accessible over HTTPS."
            )
        else:
            results.append(
                "VMC certificate URL is unreachable — verify it is hosted "
                "and publicly accessible over HTTPS"
            )
            overall = "warn"
            suggestions.append(
                f"The VMC URL could not be reached. Verify DNS resolution and "
                f"that the file is served at: {vmc_url}"
            )
    else:
        results.append(
            "No VMC (a=) in BIMI record — logo will not display in Gmail or "
            "Apple Mail. Yahoo and Fastmail support self-asserted BIMI without a VMC."
        )
        overall = "warn"
        suggestions.append(
            "A Verified Mark Certificate (VMC) is required by Gmail and Apple Mail. "
            "VMCs are issued by DigiCert and require your logo to be a registered "
            "trademark. They cost several hundred dollars per year."
        )
        suggestions.append(
            "Without a VMC, BIMI will still function on Yahoo Mail and Fastmail — "
            "useful for testing and for reaching users on those platforms."
        )
        suggestions.append(
            "To add a VMC later: obtain one from DigiCert, host the .pem file over "
            "HTTPS, and add a=<url> to your BIMI DNS record."
        )

    if not logo_url:
        results.append(
            "No logo URL (l=) found in BIMI record — a logo URL is required"
        )
        return (
            results,
            "missing",
            "BIMI record is present but contains no logo URL (l=). "
            "The logo will not display in any email client.",
            [
                "Add l=https://yourdomain.com/path/to/logo.svg to your BIMI "
                "DNS record, e.g.: v=BIMI1; l=https://yourdomain.com/bimi/logo.svg",
                "The SVG must be served over HTTPS and conform to the BIMI "
                "SVG Tiny P/S specification.",
            ],
        )

    status_code, headers, body = fetch_url_full(logo_url)

    if status_code is None:
        results.append(f"Error fetching logo at {logo_url}: {body}")
        return (
            results,
            "missing",
            "BIMI record is configured but the logo SVG could not be fetched.",
            suggestions + [
                f"Verify the logo URL is publicly accessible: {logo_url}",
                "Ensure the file is served over HTTPS with a valid, trusted certificate.",
                f"Test with: curl -I {logo_url}",
            ],
        )
    if status_code != 200:
        results.append(f"Logo URL returned HTTP {status_code} at {logo_url}")
        return (
            results,
            "missing",
            f"BIMI logo file is inaccessible (HTTP {status_code}).",
            suggestions + [
                f"The logo URL returned HTTP {status_code}. Check your web server "
                "configuration and ensure the file exists at the specified path.",
                f"Test with: curl -I {logo_url}",
            ],
        )

    results.append(f"Logo SVG accessible at {logo_url}")

    content_type = headers.get('Content-Type', headers.get('content-type', ''))
    svg_issues, svg_warnings, svg_suggestions = _validate_bimi_svg(body, content_type)

    for issue in svg_issues:
        results.append(f"SVG error: {issue}")
    for warning in svg_warnings:
        results.append(f"SVG warning: {warning}")

    if svg_issues:
        overall = "missing"
    elif svg_warnings and overall == "ok":
        overall = "warn"

    if not svg_issues:
        results.append(
            "SVG passes all required BIMI Tiny P/S checks"
            + (" (see warnings above)" if svg_warnings else "")
        )

    suggestions.extend(svg_suggestions)

    if overall == "ok":
        summary = (
            "BIMI logo is correctly configured with a valid VMC and passes "
            "SVG Tiny P/S validation. The logo should display in all supporting "
            "email clients."
        )
    elif overall == "warn":
        if not vmc_url:
            summary = (
                "BIMI is partially configured. Without a VMC the logo will only "
                "display in providers that support self-asserted BIMI (Yahoo, "
                "Fastmail). Gmail and Apple Mail require a VMC."
            )
        else:
            summary = (
                "BIMI logo is accessible but has configuration warnings. "
                "The logo may not display consistently across all email clients."
            )
    else:
        summary = (
            "BIMI has critical errors — the logo is missing, inaccessible, or "
            "fails SVG Tiny P/S validation. It will not display in any email client."
        )

    return results, overall, summary, suggestions


# ---------------------------------------------------------------------------
# State tracking, audit logging, and notifications
# ---------------------------------------------------------------------------

def load_state(path, domain):
    """
    Load state file for the given domain. Returns a fresh state dict if the
    file is absent, unreadable, or belongs to a different domain.
    """
    try:
        data = json.loads(Path(path).read_text())
        if data.get('domain') == domain:
            return data
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return {'domain': domain, 'last_run': None, 'checks': {}}


def save_state(path, state):
    """Persist state to disk. Prints a warning on failure but never raises."""
    try:
        Path(path).write_text(json.dumps(state, indent=2))
    except OSError as e:
        print(f"  Warning: could not write state file {path}: {e}", file=sys.stderr)


def append_audit_log(path, domain, timestamp, results_by_key):
    """
    Append a single JSON line to the audit log recording the outcome of
    every check in this run.
    """
    entry = {
        'timestamp': timestamp,
        'domain':    domain,
        'results':   {key: tup[2] for key, tup in results_by_key.items()},
    }
    try:
        with open(path, 'a') as fh:
            fh.write(json.dumps(entry) + '\n')
    except OSError as e:
        print(f"  Warning: could not write audit log {path}: {e}", file=sys.stderr)


def send_ntfy(url, title, body, status):
    """
    POST a notification to an ntfy topic URL.
    Failures are printed as warnings but never raise — a notification failure
    must never abort the main script.
    """
    try:
        requests.post(
            url,
            headers={
                'Title':        title,
                'Priority':     _NTFY_PRIORITY[status],
                'Tags':         _NTFY_TAGS[status],
                'Content-Type': 'text/plain; charset=utf-8',
            },
            data=body.encode('utf-8'),
            timeout=10,
        )
    except requests.RequestException as e:
        print(f"  Warning: ntfy notification failed: {e}", file=sys.stderr)


def ping_healthcheck(url):
    """
    Ping a healthchecks.io-compatible dead man's switch URL.
    Called unconditionally at the end of every run so an alert fires if the
    cron job itself stops executing.
    """
    try:
        requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"  Warning: healthcheck ping failed: {e}", file=sys.stderr)


def process_state(domain, results_by_key, state, ntfy_url, now):
    """
    For each delivery-critical check, compare the current result against
    saved state and apply the notification rules:

      Degradation (green → amber/red):
        Notification fires only if the check has been non-green for 2 or more
        consecutive runs AND the episode originated from a green state.
        warn → missing transitions are not re-notified.

      Recovery (any non-green → green):
        Notification fires immediately on the first green result.

    State is updated in-place. Returns a list of human-readable strings
    describing any notifications that were sent (for terminal display).
    """
    sent = []

    for key in DELIVERY_CRITICAL_KEYS:
        if key not in results_by_key:
            continue

        label, _, curr_status, _, _ = results_by_key[key]
        prev = state['checks'].get(key)

        # ── First run for this check: establish baseline, no notification ──
        if prev is None:
            state['checks'][key] = {
                'status':                    curr_status,
                'consecutive_non_green':     0 if curr_status == 'ok' else 1,
                'episode_started_from_green': False,
                'notified':                  False,
                'last_changed':              now,
                'last_run':                  now,
            }
            continue

        prev_status = prev['status']

        # ── Recovery ──────────────────────────────────────────────────────
        if curr_status == 'ok':
            if prev_status != 'ok':
                msg = (
                    f"{label} has returned to green for {domain}.\n"
                    f"Previous status: {_STATUS_COLOUR[prev_status]}"
                )
                if ntfy_url:
                    send_ntfy(
                        ntfy_url,
                        title=f"[RECOVERED] {label} - {domain}",
                        body=msg,
                        status='ok',
                    )
                sent.append(
                    f"Recovery: {label} "
                    f"({_STATUS_COLOUR[prev_status]} \u2192 green)"
                )
            state['checks'][key] = {
                'status':                    'ok',
                'consecutive_non_green':     0,
                'episode_started_from_green': False,
                'notified':                  False,
                'last_changed': now if prev_status != 'ok' else prev.get('last_changed', now),
                'last_run':                  now,
            }
            continue

        # ── Non-green: determine whether this is a new episode from green ─
        if prev_status == 'ok':
            new_consecutive     = 1
            started_from_green  = True
        else:
            new_consecutive    = prev.get('consecutive_non_green', 1) + 1
            started_from_green = prev.get('episode_started_from_green', False)

        already_notified = prev.get('notified', False)

        should_notify = (
            ntfy_url
            and started_from_green
            and not already_notified
            and new_consecutive >= 2
        )

        if should_notify:
            colour_label = _STATUS_COLOUR[curr_status]
            msg = (
                f"{label} has degraded from green to {colour_label} for {domain}.\n"
                f"Confirmed on {new_consecutive} consecutive checks.\n"
                "Review your DNS configuration."
            )
            send_ntfy(
                ntfy_url,
                title=f"[ALERT] {label} degraded - {domain}",
                body=msg,
                status=curr_status,
            )
            sent.append(
                f"Degradation alert: {label} "
                f"(green \u2192 {colour_label}, {new_consecutive} consecutive runs)"
            )

        state['checks'][key] = {
            'status':                    curr_status,
            'consecutive_non_green':     new_consecutive,
            'episode_started_from_green': started_from_green,
            'notified':                  already_notified or bool(should_notify),
            'last_changed': now if prev_status != curr_status else prev.get('last_changed', now),
            'last_run':                  now,
        }

    return sent


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def print_terminal_result(label, records, status, summary, suggestions):
    colour = _STATUS_ANSI[status]
    print(
        f"\n{colour}{label} "
        f"[{_STATUS_SYMBOL[status]} {_STATUS_LABEL[status]}]{RESET}"
    )
    print(f"  {colour}{summary}{RESET}")
    for record in records:
        print(f"  {colour}-> {record}{RESET}")
    if suggestions:
        print(f"  {CYAN}How to fix:{RESET}")
        for suggestion in suggestions:
            lines = suggestion.splitlines()
            for i, line in enumerate(lines):
                prefix = f"  {CYAN}   [i] " if i == 0 else f"  {CYAN}       "
                print(f"{prefix}{line}{RESET}")


def generate_html_report(domain, results):
    """
    results: list of (label, records, status, summary, suggestions)
    Returns a complete, self-contained HTML string.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    statuses = [r[2] for r in results]
    n_pass = sum(1 for s in statuses if s == 'ok')
    n_warn = sum(1 for s in statuses if s == 'warn')
    n_fail = sum(1 for s in statuses if s == 'missing')

    if n_fail == 0 and n_warn == 0:
        posture_msg    = "All checks passed"
        posture_color  = "#14532d"
        posture_bg     = "#f0fdf4"
        posture_border = "#16a34a"
    elif n_fail > 0:
        posture_msg    = f"{n_fail} critical issue(s) found, {n_warn} warning(s)"
        posture_color  = "#7f1d1d"
        posture_bg     = "#fef2f2"
        posture_border = "#dc2626"
    else:
        posture_msg    = f"{n_warn} warning(s) — no critical issues"
        posture_color  = "#78350f"
        posture_bg     = "#fffbeb"
        posture_border = "#d97706"

    cards = []
    for label, records, status, summary, suggestions in results:
        tc  = _HTML_TEXT[status]
        bc  = _HTML_BORDER[status]
        bg  = _HTML_BG[status]
        bbg = _HTML_BADGE_BG[status]
        btc = _HTML_BADGE_TEXT[status]
        sym = _STATUS_SYMBOL[status]
        lbl = _STATUS_LABEL[status]

        items_html = "\n      ".join(
            f"<li>{html_lib.escape(str(r))}</li>" for r in records
        )

        if suggestions:
            fix_items = "\n        ".join(
                f"<li>{html_lib.escape(str(s))}</li>" for s in suggestions
            )
            fix_box = f"""
    <div style="background:#f0f9ff;border:1px solid #bae6fd;border-left:3px solid #0284c7;border-radius:4px;padding:12px 16px;margin-top:14px;">
      <div style="font-size:0.78rem;font-weight:700;color:#0369a1;letter-spacing:0.04em;margin-bottom:6px;">HOW TO FIX</div>
      <ul style="margin:0;padding-left:18px;color:#0c4a6e;font-size:0.82rem;line-height:1.75;">
        {fix_items}
      </ul>
    </div>"""
        else:
            fix_box = ""

        cards.append(
            f"""  <div style="background:{bg};border-left:4px solid {bc};border-radius:6px;padding:18px 22px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.07);">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:12px;">
      <span style="font-weight:600;font-size:0.95rem;color:#1e293b;">{html_lib.escape(label)}</span>
      <span style="background:{bbg};color:{btc};border:1px solid {bc};border-radius:12px;padding:2px 11px;font-size:0.75rem;font-weight:700;letter-spacing:0.05em;white-space:nowrap;flex-shrink:0;">{sym} {lbl}</span>
    </div>
    <p style="margin:0 0 12px 0;color:{tc};font-size:0.9rem;line-height:1.55;">{html_lib.escape(summary)}</p>
    <ul style="margin:0;padding-left:18px;color:#374151;font-size:0.82rem;line-height:1.75;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;">
      {items_html}
    </ul>{fix_box}
  </div>"""
        )

    cards_str = "\n".join(cards)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNS Email Security Report &mdash; {html_lib.escape(domain)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 24px 16px 56px;
    background: #f8fafc;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #1e293b;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 800px; margin: 0 auto; }}
  .hdr {{
    background: #1e293b;
    color: #f1f5f9;
    border-radius: 8px;
    padding: 22px 28px;
    margin-bottom: 18px;
  }}
  .hdr-label {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.1em; color: #64748b; margin-bottom: 6px; }}
  .hdr-domain {{ font-size: 1.45rem; font-weight: 800; color: #e2e8f0; word-break: break-all; }}
  .hdr-meta {{ margin-top: 8px; font-size: 0.8rem; color: #64748b; }}
  .posture {{
    display: flex; align-items: center; justify-content: space-between;
    gap: 12px; border-radius: 6px; padding: 12px 18px; margin-bottom: 16px;
    border-left: 4px solid {posture_border}; background: {posture_bg};
    color: {posture_color}; font-weight: 600; font-size: 0.9rem; flex-wrap: wrap;
  }}
  .posture-counts {{ font-weight: 400; color: #64748b; font-size: 0.82rem; }}
  .legend {{ display: flex; gap: 18px; margin-bottom: 20px; flex-wrap: wrap; }}
  .legend-item {{ display: flex; align-items: center; gap: 7px; font-size: 0.8rem; color: #64748b; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  .footer {{ margin-top: 32px; text-align: center; font-size: 0.75rem; color: #94a3b8; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div class="hdr-label">DNS Email Security Report</div>
    <div class="hdr-domain">{html_lib.escape(domain)}</div>
    <div class="hdr-meta">Generated {timestamp}</div>
  </div>
  <div class="posture">
    <span>Overall posture: {html_lib.escape(posture_msg)}</span>
    <span class="posture-counts">{n_pass} pass &nbsp;/&nbsp; {n_warn} warn &nbsp;/&nbsp; {n_fail} fail</span>
  </div>
  <div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background:#16a34a;"></div>Pass &mdash; correctly configured</div>
    <div class="legend-item"><div class="legend-dot" style="background:#d97706;"></div>Warning &mdash; present but suboptimal</div>
    <div class="legend-item"><div class="legend-dot" style="background:#dc2626;"></div>Fail &mdash; missing or critically misconfigured</div>
  </div>
{cards_str}
  <div class="footer">
    Generated by check_dns &mdash; MX &middot; SPF &middot; DKIM &middot; DMARC &middot; MTA-STS &middot; BIMI
  </div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    default_state_file = str(Path(__file__).parent / 'check_dns_state.json')

    parser = argparse.ArgumentParser(
        description="Check email-related DNS records and security policy configuration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s example.com\n"
            "  %(prog)s example.com --html > report.html\n"
            "  %(prog)s example.com --ntfy-url https://ntfy.sh/my-topic\n"
            "  %(prog)s example.com --html --ntfy-url https://ntfy.sh/my-topic "
            "--audit-log /var/log/dns_audit.jsonl "
            "--healthcheck-url https://hc-ping.com/your-uuid "
            "> /var/www/html/dns-report/index.html\n"
        )
    )
    parser.add_argument(
        "domain", nargs="?",
        help="Domain name to check"
    )
    parser.add_argument(
        "--html", action="store_true",
        help=(
            "Output a self-contained HTML report instead of terminal output. "
            "Pipe to a file: check_dns.py example.com --html > report.html"
        ),
    )
    parser.add_argument(
        "--state-file", default=default_state_file, metavar="PATH",
        help=(
            "Path to the JSON state file used to detect status regressions. "
            f"Defaults to check_dns_state.json in the script directory. "
            "Created automatically on first run."
        ),
    )
    parser.add_argument(
        "--audit-log", default=None, metavar="PATH",
        help=(
            "Path to an append-only JSON lines audit log recording the result "
            "of every check on every run. Optional."
        ),
    )
    parser.add_argument(
        "--ntfy-url", default=None, metavar="URL",
        help=(
            "ntfy topic URL to receive push notifications when a "
            "delivery-critical check (MX, SPF, DKIM, DMARC, MTA-STS) degrades "
            "from green to amber/red (confirmed over 2 consecutive runs), or "
            "recovers back to green. "
            "Example: https://ntfy.sh/my-dns-alerts or "
            "http://ntfy.yourdomain.com/my-topic"
        ),
    )
    parser.add_argument(
        "--healthcheck-url", default=None, metavar="URL",
        help=(
            "healthchecks.io-compatible ping URL. Sent as an unconditional GET "
            "request at the end of every successful run, providing a dead man's "
            "switch to alert you if the cron job itself stops running. "
            "Example: https://hc-ping.com/your-uuid"
        ),
    )

    args   = parser.parse_args()
    domain = args.domain or input("Enter domain to check: ").strip()

    dkim_selectors = check_dkim.__defaults__[0]
    dkim_label     = f"DKIM Record (selectors: {', '.join(dkim_selectors)})"

    # Each entry: (display_label, state_key, check_function)
    checks = [
        ("MX Records",     "mx",      check_mx),
        ("SPF Record",     "spf",     check_spf),
        (dkim_label,       "dkim",    check_dkim),
        ("DMARC Record",   "dmarc",   check_dmarc),
        ("MTA-STS Record", "mta_sts", check_mta_sts),
        ("BIMI Record",    "bimi",    check_bimi),
    ]

    # Run all checks
    results_by_key = {}
    for label, key, check_func in checks:
        records, status, summary, suggestions = check_func(domain)
        results_by_key[key] = (label, records, status, summary, suggestions)

    now = datetime.now(timezone.utc).isoformat(timespec='seconds')

    # State tracking and notifications
    state         = load_state(args.state_file, domain)
    notifications = process_state(domain, results_by_key, state, args.ntfy_url, now)
    state['last_run'] = now
    save_state(args.state_file, state)

    # Audit log
    if args.audit_log:
        append_audit_log(args.audit_log, domain, now, results_by_key)

    # Dead man's switch
    if args.healthcheck_url:
        ping_healthcheck(args.healthcheck_url)

    # Build ordered list for renderers
    gathered = []
    for label, key, _ in checks:
        gathered.append(results_by_key[key])

    if args.html:
        print(generate_html_report(domain, gathered))
    else:
        sep = "\u2500" * 52
        print(f"\n{sep}")
        print(f"  DNS Email Security Report \u2014 {domain}")
        print(sep)
        for label, records, status, summary, suggestions in gathered:
            print_terminal_result(label, records, status, summary, suggestions)
        if notifications:
            print(f"\n{CYAN}  Notifications sent this run:{RESET}")
            for note in notifications:
                print(f"  {CYAN}  \u2192 {note}{RESET}")
        print()


if __name__ == "__main__":
    main()
