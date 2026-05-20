#!/usr/bin/env python3
"""
check_dns.py — Audit email-related DNS records and security policies.

Checks: MX, SPF, DKIM, DMARC, MTA-STS, DNSSEC, DANE, CAA, BIMI.
Produces colour-coded terminal output or a self-contained HTML report.
Optional state tracking with ntfy notifications on degradation/recovery,
JSONL audit logging, and healthchecks.io dead man's switch pings.

Project: https://github.com/alan-berger/dnstoolbox
License: MIT
"""
import argparse
import html as html_lib
import ipaddress
import json
import re
import socket
import ssl
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.rdatatype
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
# HTML colour palette (used by the self-contained HTML report renderer)
# ---------------------------------------------------------------------------
_HTML_TEXT       = {'ok': '#14532d', 'warn': '#78350f', 'missing': '#7f1d1d'}
_HTML_BORDER     = {'ok': '#16a34a', 'warn': '#d97706', 'missing': '#dc2626'}
_HTML_BG         = {'ok': '#f0fdf4', 'warn': '#fffbeb', 'missing': '#fef2f2'}
_HTML_BADGE_BG   = {'ok': '#dcfce7', 'warn': '#fef3c7', 'missing': '#fee2e2'}
_HTML_BADGE_TEXT = {'ok': '#15803d', 'warn': '#b45309', 'missing': '#b91c1c'}

# ---------------------------------------------------------------------------
# Default DKIM selectors probed when --dkim-selectors is not supplied.
#
# These cover the most common mail providers:
#   default   — generic / many self-hosted setups (e.g. docker-mailserver)
#   google    — Google Workspace
#   selector1 — Microsoft 365 (primary)
#   selector2 — Microsoft 365 (secondary, used during key rotation)
#   k1        — Mailchimp, SendGrid, Mandrill
#   s1        — Amazon SES, others
#   mail      — Postmark, various
#   dkim      — Fastmail, various self-hosted setups
#
# Override at runtime with --dkim-selectors selector1,selector2,...
# The actual selector for any given domain can be found by inspecting the
# DKIM-Signature: s= tag in a delivered email.
# ---------------------------------------------------------------------------
DEFAULT_DKIM_SELECTORS = (
    'default', 'google', 'selector1', 'selector2',
    'k1', 's1', 'mail', 'dkim',
)

# ---------------------------------------------------------------------------
# Input validation and sanitisation
#
# DNS data ultimately reaches the HTML output via html_lib.escape() in
# generate_html_report(), which is the primary XSS defence. The functions
# below provide a second, independent layer applied at the point of ingestion:
#
#   validate_domain()       — called once at startup before any DNS queries.
#   _sanitise_dns_value()   — applied to every raw DNS record value returned
#                             by get_dns_records().
#   _sanitise_tag_value()   — caps short values extracted from DNS record tags
#                             (e.g. DMARC p=, MTA-STS mode:) before they are
#                             interpolated into human-readable messages.
#   _validate_fetch_url()   — validates URLs extracted from DNS records before
#                             they are passed to requests.get(). This prevents
#                             SSRF: an attacker who controls your DNS could
#                             otherwise set BIMI l= to an internal metadata
#                             endpoint (e.g. http://169.254.169.254/...) or a
#                             file:// URI.
# ---------------------------------------------------------------------------

# RFC 1035 §2.3.4 + RFC 5321: labels max 63 chars, total max 253 chars.
_DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$',
    re.IGNORECASE,
)

_MAX_DNS_VALUE_LEN = 2048   # per-record cap (single TXT RR theoretical max is 65535 B)
_MAX_HTTP_BODY     = 65536  # 64 KB — MTA-STS policies and BIMI SVGs are tiny in practice
_MAX_URL_LEN       = 2048   # cap on URLs extracted from DNS records
_MAX_TAG_VALUE_LEN = 64     # cap on short tag values embedded in messages

# Hostnames / patterns that must never be fetched (SSRF guards)
_BLOCKED_HOST_RE = re.compile(
    r'^(?:localhost|.*\.local|.*\.internal|.*\.localdomain|.*\.arpa)$',
    re.IGNORECASE,
)


def validate_domain(domain: str) -> str:
    """
    Validate and normalise a domain name.

    Returns the lowercased, trailing-dot-stripped domain on success, or
    raises ValueError with a human-readable message on failure.  Called
    once at startup before any DNS queries or HTML generation.
    """
    domain = domain.strip().lower().rstrip('.')
    if not domain:
        raise ValueError("Domain name cannot be empty.")
    if len(domain) > 253:
        raise ValueError(
            f"Domain name is too long ({len(domain)} chars; RFC 1035 maximum is 253)."
        )
    if not _DOMAIN_RE.match(domain):
        raise ValueError(
            f"Invalid domain name: {domain!r}. "
            "Only letters, digits, hyphens, and dots are permitted."
        )
    return domain


def _sanitise_dns_value(value: str, max_len: int = _MAX_DNS_VALUE_LEN) -> str:
    """
    Sanitise a single DNS record value before it enters the processing pipeline.

    Strips non-printable characters (they have no legitimate place in DNS
    record values and could confuse downstream string handling), then caps
    the length so a crafted large TXT record cannot bloat the HTML output.
    Applied to every value returned by get_dns_records().
    """
    value = ''.join(ch for ch in value if ch.isprintable())
    if len(value) > max_len:
        value = value[:max_len] + f' … [value truncated: {len(value) - max_len} chars omitted]'
    return value


def _sanitise_tag_value(value: str, max_len: int = _MAX_TAG_VALUE_LEN) -> str:
    """
    Cap and strip a short tag value (e.g. DMARC p=, MTA-STS mode:) before
    it is interpolated into a human-readable diagnostic message.

    The value has already been through _sanitise_dns_value at the DNS layer
    (for DNS-sourced data) or via HTTP body capping (for policy-file data).
    This extra cap keeps error messages readable and provides defence-in-depth
    in case the value reaches this point via an unexpected code path.
    """
    value = ''.join(ch for ch in value if ch.isprintable())
    if len(value) > max_len:
        value = value[:max_len] + '…'
    return value


def _validate_fetch_url(url: str) -> tuple:
    """
    Validate that a URL extracted from a DNS record is safe to fetch.

    Returns (True, '') on success or (False, reason_str) on failure.

    Accepts only HTTPS URLs with a valid public hostname.  Blocks:
      - Non-HTTPS schemes (http://, file://, ftp://, etc.)
      - IP address hostnames (prevents metadata-service SSRF on cloud hosts)
      - Loopback, link-local, private ranges (via ipaddress module)
      - Localhost / .local / .internal / .arpa hostnames
      - URLs exceeding _MAX_URL_LEN characters
    """
    if not url:
        return False, "URL is empty."
    if len(url) > _MAX_URL_LEN:
        return False, (
            f"URL length ({len(url)} chars) exceeds the maximum permitted "
            f"({_MAX_URL_LEN} chars)."
        )

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"URL could not be parsed: {exc}"

    if parsed.scheme != 'https':
        return False, (
            f"Only HTTPS URLs are permitted in DNS records; "
            f"got scheme '{parsed.scheme}'."
        )

    hostname = parsed.hostname or ''
    if not hostname:
        return False, "URL contains no hostname."

    # Block IP address literals — both IPv4 and IPv6.
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_loopback or addr.is_link_local or addr.is_private or addr.is_reserved:
            return False, (
                f"URL hostname '{hostname}' resolves to a non-public address range."
            )
        return False, (
            f"URL hostname must be a domain name, not an IP address ('{hostname}')."
        )
    except ValueError:
        pass  # Not an IP address — that is what we want.

    if _BLOCKED_HOST_RE.match(hostname):
        return False, f"URL hostname '{hostname}' is not permitted."

    return True, ''


# ---------------------------------------------------------------------------
# Delivery-critical checks — the only ones tracked for state changes and
# notifications. BIMI is intentionally excluded as it does not affect
# email deliverability.
# ---------------------------------------------------------------------------
DELIVERY_CRITICAL_KEYS = {'mx', 'spf', 'dkim', 'dmarc', 'mta_sts', 'dnssec', 'dane', 'caa'}

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
        return [_sanitise_dns_value(rdata.to_text().strip('"')) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []


def fetch_url(url):
    """Returns (status_code, body) or (None, error_str)."""
    try:
        r = requests.get(url, headers=_HTTP_HEADERS, timeout=30, allow_redirects=True)
        return r.status_code, r.text[:_MAX_HTTP_BODY]
    except requests.RequestException as e:
        return None, str(e)


def fetch_url_full(url):
    """Returns (status_code, headers_dict, body) or (None, {}, error_str)."""
    try:
        r = requests.get(url, headers=_HTTP_HEADERS, timeout=30, allow_redirects=True)
        return r.status_code, dict(r.headers), r.text[:_MAX_HTTP_BODY]
    except requests.RequestException as e:
        return None, {}, str(e)


def _fetch_smtp_certificate(hostname, port=25, timeout=10):
    """
    Connect to an SMTP server and retrieve the TLS certificate presented.

    Returns (cert_der_bytes, None) on success or (None, error_str) on failure.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            # Read SMTP banner
            sock.recv(1024)
            # Initiate STARTTLS
            sock.sendall(b"STARTTLS\r\n")
            response = sock.recv(1024)

            if not response.startswith(b"220"):
                return None, f"SMTP server at {hostname}:{port} did not respond with 220 after STARTTLS"

            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                return cert_der, None
    except socket.timeout:
        return None, f"Connection to {hostname}:{port} timed out"
    except socket.gaierror as e:
        return None, f"Failed to resolve hostname {hostname}: {e}"
    except Exception as e:
        return None, f"Error fetching certificate from {hostname}:{port}: {e}"


# ---------------------------------------------------------------------------
# SPF helpers (RFC 7208)
#
# SPF terms are prefix-determined: the mechanism keyword or modifier name
# unambiguously fixes both the term's type and its DNS-lookup cost. These
# helpers exploit that by tokenising the record and classifying each term
# against the closed, finite set of SPF terms, rather than substring-matching
# the raw string (which would otherwise falsely match 'a' inside IPv6
# literals such as 2c1a::1).
# ---------------------------------------------------------------------------

def _count_spf_lookups(spf):
    """
    Count DNS-lookup-consuming SPF mechanisms per RFC 7208 §4.6.4.

    Lookup-consuming: include, a, mx, ptr, exists, and the redirect= modifier.
    Zero-cost: ip4, ip6, all, exp=, and the v=spf1 version tag. ip4:/ip6:
    address literals never count regardless of their content.

    Counts the top-level record only — does NOT recurse into include:/redirect=
    targets, so the true effective total across the full evaluation tree can be
    higher than the figure reported here.
    """
    lookup_prefixes = ('include:', 'exists:', 'redirect=')
    count = 0
    for term in spf.split():
        # Strip a leading qualifier (+ - ~ ?); modifiers carry none.
        bare = term[1:] if term[:1] in '+-~?' else term
        low = bare.lower()
        if low.startswith(lookup_prefixes):
            count += 1
        elif low == 'a' or low.startswith(('a:', 'a/')):
            count += 1
        elif low == 'mx' or low.startswith(('mx:', 'mx/')):
            count += 1
        elif low == 'ptr' or low.startswith('ptr:'):
            count += 1
    return count


def _validate_spf_ip_literals(spf):
    """
    Validate every ip4:/ip6: mechanism. Returns a list of human-readable
    error strings (empty when all literals are well-formed).

    Checks: the value parses as an address or CIDR network, and its family
    matches the keyword (no IPv6 behind ip4:, no IPv4 behind ip6:). A bare
    address is accepted as a single host; host bits set in a CIDR are
    tolerated (strict=False) since SPF receivers do not reject on that.

    Caveat: ipaddress also accepts integer/packed forms (e.g. ip4:3232235521)
    which are not valid SPF syntax. This is a rare edge and not flagged.
    """
    errors = []
    for term in spf.split():
        bare = term[1:] if term[:1] in '+-~?' else term
        low = bare.lower()
        if low.startswith('ip4:'):
            value = bare[4:]
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                errors.append(f"ip4:{value} is not a valid IPv4 literal ({exc})")
                continue
            if net.version != 4:
                errors.append(f"ip4:{value} is an IPv6 address behind ip4:")
        elif low.startswith('ip6:'):
            value = bare[4:]
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                errors.append(f"ip6:{value} is not a valid IPv6 literal ({exc})")
                continue
            if net.version != 6:
                errors.append(f"ip6:{value} is an IPv4 address behind ip6:")
    return errors


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
    lookup_count = _count_spf_lookups(spf)
    ip_errors = _validate_spf_ip_literals(spf)
    records = [spf, f"DNS Lookups: {lookup_count}/10"]
    for err in ip_errors:
        records.append(f"Syntax: {err}")

    if lookup_count > 10:
        return (
            records,
            "warn",
            f"SPF record has {lookup_count} DNS lookups, exceeding the RFC 7208 "
            "limit of 10. Receiving servers may discard the record entirely, "
            "allowing spoofed mail to pass SPF checks.",
            [
                "Use an SPF flattening tool (e.g. dmarcian SPF Surveyor, mxtoolbox) "
                "to resolve include: chains into direct IP ranges, reducing lookup "
                "count.",
                "Remove redundant mechanisms — if both 'a' and 'mx' resolve to the "
                "same IP address, one can be dropped.",
                "Check whether any include: targets themselves have deep lookup "
                "chains that contribute to the total count.",
                "After flattening, keep your SPF record updated if your provider "
                "changes their IP ranges, as flattened records do not update "
                "automatically.",
            ],
        )

    if ip_errors:
        return (
            records,
            "warn",
            f"SPF record contains {len(ip_errors)} malformed IP literal(s). "
            "Per RFC 7208 §4.6, a syntactically invalid term causes receivers to "
            "return PermError; most treat PermError as an SPF failure, so "
            "legitimate mail may be rejected or marked as spam.",
            [
                "Correct the malformed ip4:/ip6: term(s) listed above. ip4: takes "
                "a dotted-quad address or CIDR (e.g. ip4:192.0.2.0/24); ip6: takes "
                "an IPv6 address or CIDR (e.g. ip6:2001:db8::/32).",
                "Check the address family matches the keyword — an IPv6 address "
                "must use ip6:, not ip4:, and vice versa.",
                "Verify the published record with: dig TXT yourdomain.com | grep spf",
            ],
        )

    return (
        records,
        "ok",
        f"SPF record is valid with {lookup_count} DNS lookup(s) "
        "(limit is 10, RFC 7208). Authorised senders are correctly defined.",
        [],
    )


def check_dkim(domain, selectors=DEFAULT_DKIM_SELECTORS):
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
                "may use a different one — a missing result here does not necessarily "
                "mean DKIM is absent.",
                "To find your actual selector: inspect the DKIM-Signature: header in "
                "a delivered email (viewable via 'Show original' or 'View source' in "
                "most mail clients) and look for the s= tag, e.g. s=google or s=smtp.",
                "Once you know your selector, re-run with: "
                "check_dns.py yourdomain.com --dkim-selectors yourselector",
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
        f"DMARC policy value '{_sanitise_tag_value(policy)}' is not recognised. "
        "Expected: none, quarantine, or reject.",
        [
            f"Check your DMARC record for a typo in the p= tag (found: '{_sanitise_tag_value(policy)}'). "
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
            f"Mode: unrecognised value '{_sanitise_tag_value(mode)}' "
            "(expected: enforce, testing, or none)"
        )
        suggestions.append(
            f"Fix the mode field in your policy file. "
            f"Found '{_sanitise_tag_value(mode)}'; "
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
        _raw_max_age = _sanitise_tag_value(str(policy.get('max_age', '')))
        hard_errs.append(
            f"max_age: invalid non-integer value '{_raw_max_age}'"
        )
        suggestions.append(
            "Ensure max_age is a plain integer (number of seconds), "
            f"e.g.: max_age: 86400 — found: '{_raw_max_age}'"
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
                results.append(f"MX pattern '{pattern}': matches DNS MX record ✓")
            else:
                results.append(f"MX pattern '{pattern}': no matching DNS MX record ✗")
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
# DNSSEC (RFC 4033-4035)
# ---------------------------------------------------------------------------

def check_dnssec(domain):
    """
    Check DNSSEC by looking for DNSKEY records at the apex.

    This is a structural check only — it does not walk the chain of trust
    from the root. For a full validation use 'dig +dnssec' or a validating
    resolver.
    """
    try:
        dnskey_records = get_dns_records(domain, 'DNSKEY')

        if not dnskey_records:
            return (
                ["No DNSKEY records found"],
                "missing",
                "DNSSEC is not configured. DNS responses cannot be cryptographically "
                "verified, allowing attackers to forge DNS records.",
                [
                    "Enable DNSSEC at your DNS provider — most providers (Cloudflare, "
                    "Route 53, Namecheap, etc.) offer one-click DNSSEC enablement.",
                    "Once enabled, your provider will publish DNSKEY records and a "
                    "DS record at the registry. Verify: dig DNSKEY yourdomain.com",
                    "If your registrar differs from your DNS provider, ensure the DS "
                    "record from your DNS provider is added at your registrar.",
                    "DNSSEC is a prerequisite for DANE to provide security; without "
                    "DNSSEC, TLSA records can be forged.",
                ],
            )

        results = [f"Found {len(dnskey_records)} DNSKEY record(s)"]
        results.extend(dnskey_records[:2])  # Show first 2 DNSKEY records
        results.append("DNSSEC structure: DNSKEY records published")

        return (
            results,
            "ok",
            "DNSSEC is enabled and DNSKEY records are published. DNS responses "
            "can be cryptographically verified.",
            [],
        )
    except Exception as e:
        return (
            [str(e)[:100]],
            "missing",
            "DNSSEC configuration could not be verified.",
            [
                "Check that DNSSEC is enabled at your DNS provider.",
                "Verify with: dig DNSKEY yourdomain.com",
                "Test chain-of-trust validation with: dig +dnssec yourdomain.com — "
                "the response should contain the 'ad' (Authenticated Data) flag.",
            ],
        )


# ---------------------------------------------------------------------------
# DANE (RFC 6698)
# ---------------------------------------------------------------------------

def check_dane(domain, mx_hostname=None):
    """
    Check DANE configuration for the domain's mail server.

    Verifies:
    1. TLSA record exists at _25._tcp.<mx_hostname>
    2. Certificate retrieved from the mail server matches the TLSA record hash

    Note: DANE requires DNSSEC to provide security; the DNSSEC check is run
    separately by this script. If mx_hostname is not provided, the domain's
    MX records are queried to discover it.
    """
    results = []

    # Get MX record if not provided
    if not mx_hostname:
        mx_records = get_dns_records(domain, 'MX')
        if not mx_records:
            return (
                ["No MX records found; DANE check skipped"],
                "missing",
                "Cannot check DANE without MX records.",
                [],
            )

        # Extract hostname from MX record (format: priority hostname)
        mx_parts = mx_records[0].split()
        if len(mx_parts) < 2:
            return (
                ["MX record format invalid"],
                "missing",
                "MX record format is invalid; cannot extract mail server hostname.",
                [],
            )
        mx_hostname = mx_parts[1].rstrip('.')

    # Construct TLSA record name
    tlsa_name = f"_25._tcp.{mx_hostname}"
    tlsa_records = get_dns_records(tlsa_name, 'TLSA')

    if not tlsa_records:
        return (
            [f"No TLSA record found at {tlsa_name}"],
            "missing",
            "DANE is not configured. SMTP connections cannot be verified against DNS.",
            [
                f"Add a TLSA record at {tlsa_name} with format:",
                f"_25._tcp.{mx_hostname}.  3600  IN  TLSA  3 1 1 <sha256-hash>",
                "The hash is the SHA-256 of the mail server's public key (TLSA 3 1 1).",
                f"Generate the hash: echo | openssl s_client -connect {mx_hostname}:25 "
                "-starttls smtp 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey "
                "-pubin -outform DER | openssl dgst -sha256 -hex | cut -d' ' -f2",
                "DANE requires DNSSEC to be enabled on your domain for security.",
                f"Once published, verify with: dig TLSA {tlsa_name}",
            ],
        )

    results.append(f"Mail server: {mx_hostname}")
    results.extend(tlsa_records)

    # Parse TLSA record (format: usage selector matching-type hash)
    tlsa_parts = tlsa_records[0].split()
    if len(tlsa_parts) < 4:
        return (
            results + ["TLSA record format invalid"],
            "missing",
            "TLSA record format is invalid.",
            ["Ensure TLSA record follows RFC 6698: usage selector matching-type hash"],
        )

    usage, selector, matching_type, tlsa_hash = (
        tlsa_parts[0], tlsa_parts[1], tlsa_parts[2], tlsa_parts[3].lower()
    )

    # Validate TLSA format
    usage_map    = {'0': 'PKIX-TA', '1': 'PKIX-EE', '2': 'DANE-TA', '3': 'DANE-EE'}
    selector_map = {'0': 'Full Cert', '1': 'Public Key'}
    type_map     = {'1': 'SHA-256', '2': 'SHA-512'}

    if usage not in usage_map:
        return (
            results + [f"Invalid TLSA usage field: {usage}"],
            "warn",
            f"TLSA record has invalid usage value '{usage}'.",
            [f"TLSA usage should be 0-3, found {usage}. RFC 6698 recommends usage 3 (DANE-EE)."],
        )

    if selector not in selector_map:
        return (
            results + [f"Invalid TLSA selector field: {selector}"],
            "warn",
            f"TLSA record has invalid selector value '{selector}'.",
            [f"TLSA selector should be 0-1, found {selector}. Usage 1 (public key) is recommended."],
        )

    if matching_type not in type_map:
        return (
            results + [f"Invalid TLSA matching-type field: {matching_type}"],
            "warn",
            f"TLSA record has invalid matching-type value '{matching_type}'.",
            [f"TLSA matching-type should be 1 or 2, found {matching_type}. Type 1 (SHA-256) is standard."],
        )

    results.append(
        f"TLSA format: usage={usage_map[usage]}, "
        f"selector={selector_map[selector]}, type={type_map[matching_type]}"
    )

    # Fetch certificate from mail server
    cert_der, cert_error = _fetch_smtp_certificate(mx_hostname, port=25, timeout=10)

    if cert_der is None:
        return (
            results + [f"Certificate fetch failed: {cert_error}"],
            "warn",
            "Could not connect to the mail server to retrieve its certificate. "
            "Manual verification may be required.",
            [
                f"Verify connectivity to {mx_hostname}:25 — check firewall rules and SMTP service status.",
                f"Test manually: openssl s_client -connect {mx_hostname}:25 -starttls smtp",
                "If the connection fails, DANE cannot be fully validated by this script.",
                "Ensure your mail server is listening on port 25 and has STARTTLS enabled.",
            ],
        )

    # Compute expected hash from certificate
    try:
        import hashlib
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())

        if selector == '1':
            # Public key selector
            pubkey_der = cert_obj.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            # Full certificate selector
            pubkey_der = cert_der

        if matching_type == '1':
            computed_hash = hashlib.sha256(pubkey_der).hexdigest()
        elif matching_type == '2':
            computed_hash = hashlib.sha512(pubkey_der).hexdigest()
        else:
            computed_hash = None

        results.append(f"Certificate public key fetched from {mx_hostname}:25")
        results.append(f"DNS TLSA hash: {tlsa_hash}")
        results.append(f"Cert hash:    {computed_hash}")

        if computed_hash and computed_hash.lower() == tlsa_hash.lower():
            results.append("✓ Certificate hash matches TLSA record")
            return (
                results,
                "ok",
                "DANE is correctly configured. The mail server certificate is pinned "
                "in DNS and validates against the live certificate.",
                [],
            )
        else:
            return (
                results,
                "missing",
                "Certificate hash does not match TLSA record. DANE validation will fail.",
                [
                    "The live certificate does not match your TLSA record.",
                    "If you recently renewed the certificate, update the TLSA record with the new hash.",
                    f"Generate new hash: echo | openssl s_client -connect {mx_hostname}:25 "
                    "-starttls smtp 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey "
                    "-pubin -outform DER | openssl dgst -sha256 -hex | cut -d' ' -f2",
                    "For smoother certificate rotation, use TLSA usage 2 (DANE-TA) to pin "
                    "the CA public key instead of the certificate.",
                ],
            )
    except ImportError:
        return (
            results + ["cryptography library is not installed"],
            "warn",
            "Certificate was retrieved but the 'cryptography' library is not "
            "available, so hash computation cannot be performed.",
            [
                "Install the cryptography library: pip install cryptography",
                "Or install all optional dependencies: pip install -r requirements.txt",
            ],
        )
    except Exception as e:
        return (
            results + [f"Hash computation error: {str(e)[:80]}"],
            "warn",
            "Certificate was retrieved but hash computation failed.",
            [
                "Manual verification: extract the cert, compute SHA-256 of public key, "
                "and compare against the TLSA record.",
            ],
        )


# ---------------------------------------------------------------------------
# CAA (RFC 6844 — Certification Authority Authorization)
# ---------------------------------------------------------------------------

def check_caa(domain, permitted_cas=None):
    """
    Check CAA records to verify which CAs are permitted to issue certificates.

    CAA records restrict certificate issuance at the DNS layer, preventing
    unauthorised CAs from issuing certificates even if the CA system is compromised.

    Args:
        domain: The domain to check
        permitted_cas: List of permitted CA domains (defaults to ['letsencrypt.org'])
    """
    if permitted_cas is None:
        permitted_cas = ['letsencrypt.org']

    caa_records = get_dns_records(domain, 'CAA')

    if not caa_records:
        return (
            ["No CAA records found"],
            "missing",
            "CAA is not configured. Any CA can issue certificates for this domain.",
            [
                "Create a CAA record to restrict certificate issuance to authorised CAs.",
                f"For Let's Encrypt, add: yourdomain.com.  CAA  0 issue \"letsencrypt.org\"",
                "Optionally restrict wildcard issuance: yourdomain.com.  CAA  0 issuewild \"letsencrypt.org\"",
                "CAA records are checked by CAs before issuing certificates — they prevent unauthorised issuance.",
                "For maximum security, combine CAA with DNSSEC to prevent DNS forgery.",
                "Verify after publishing with: dig CAA yourdomain.com",
            ],
        )

    results = list(caa_records)
    issue_records     = []
    issuewild_records = []
    iodef_records     = []
    warnings    = []
    suggestions = []

    # Parse CAA records
    for caa in caa_records:
        parts = caa.split(None, 2)  # flags tag value
        if len(parts) < 3:
            warnings.append(f"Malformed CAA record: {caa}")
            continue

        _, tag, value = parts[0], parts[1].lower(), parts[2]
        value = value.strip().strip('"')

        if tag == 'issue':
            issue_records.append(value)
        elif tag == 'issuewild':
            issuewild_records.append(value)
        elif tag == 'iodef':
            iodef_records.append(value)

    # Check for issue records
    if not issue_records:
        return (
            results,
            "missing",
            "CAA 'issue' record is missing. Any CA can issue certificates.",
            [
                f"Add an 'issue' CAA record restricting to: "
                f"yourdomain.com.  CAA  0 issue \"{permitted_cas[0]}\"",
                "The 'issue' record is required to restrict normal (non-wildcard) certificate issuance.",
            ],
        )

    # Check if authorised CAs are listed
    found_authorised = False
    unauthorised_cas = []

    for ca in issue_records:
        ca_domain = ca.split(';')[0].strip().strip('"').lower()
        if ca_domain in [p.lower() for p in permitted_cas]:
            found_authorised = True
        else:
            unauthorised_cas.append(ca_domain)

    overall_status = "ok"

    if not found_authorised:
        results.append("⚠ No authorised CA found in issue records")
        overall_status = "warn"
        suggestions.append(
            f"Ensure at least one of your permitted CAs is listed in the 'issue' records. "
            f"Expected to find one of: {', '.join(permitted_cas)}"
        )
    else:
        authorised_list = ", ".join(
            c for c in issue_records if c.lower() in [p.lower() for p in permitted_cas]
        )
        results.append(f"✓ Authorised CA(s) found: {authorised_list}")

    if unauthorised_cas:
        results.append(f"⚠ Unauthorised CAs in issue records: {', '.join(unauthorised_cas)}")
        if overall_status == "ok":
            overall_status = "warn"
        suggestions.append(
            f"Remove unauthorised CAs from your CAA records: {', '.join(unauthorised_cas)}"
        )

    # Check IODEF
    if not iodef_records:
        results.append("ℹ No 'iodef' CAA record (violation reporting disabled)")
        suggestions.append(
            "Optionally add an 'iodef' CAA record to receive notifications from CAs "
            "if they receive invalid certificate requests for your domain: "
            "yourdomain.com.  CAA  0 iodef \"mailto:security@yourdomain.com\""
        )
    else:
        results.append(f"✓ Violation reporting configured: {', '.join(iodef_records)}")

    if overall_status == "ok":
        summary = (
            "CAA is correctly configured. Certificate issuance is restricted to "
            "authorised CA(s) and wildcard issuance is controlled."
        )
    else:
        summary = (
            "CAA is present but has warnings. Review the configuration to ensure "
            "only authorised CAs can issue certificates."
        )

    return results, overall_status, summary, suggestions


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
        url_ok, url_reason = _validate_fetch_url(vmc_url)
        if not url_ok:
            results.append(
                f"VMC URL in BIMI record is invalid and was not fetched: {url_reason}"
            )
            overall = "warn"
            suggestions.append(
                f"The a= value in your BIMI record must be a valid public HTTPS URL. "
                f"Problem: {url_reason}"
            )
        else:
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
            "A Verified Mark Certificate (VMC) or Common Mark Certificate (CMC) is "
            "required by Gmail and Apple Mail. VMCs/CMCs are issued by DigiCert; a VMC "
            "requires your logo to be a registered trademark and incurs an annual fee."
        )
        suggestions.append(
            "Without a VMC or CMC, BIMI may still function on Yahoo Mail and Fastmail — "
            "policies vary; useful for testing and for reaching users on those platforms."
        )
        suggestions.append(
            "To add a VMC or CMC later: obtain one from DigiCert, host the .pem file "
            "over HTTPS, and add a=<url> to your BIMI DNS record."
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

    url_ok, url_reason = _validate_fetch_url(logo_url)
    if not url_ok:
        results.append(
            f"BIMI logo URL (l=) is invalid and was not fetched: {url_reason}"
        )
        return (
            results,
            "missing",
            "BIMI logo URL is invalid and cannot be fetched.",
            suggestions + [
                f"The l= value in your BIMI record must be a valid public HTTPS URL. "
                f"Problem: {url_reason}",
                "Example: v=BIMI1; l=https://yourdomain.com/bimi/logo.svg",
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
            "BIMI logo is correctly configured with a valid VMC/CMC and passes "
            "SVG Tiny P/S validation. The logo should display in all supporting "
            "email clients."
        )
    elif overall == "warn":
        if not vmc_url:
            summary = (
                "BIMI is partially configured. Without a VMC/CMC the logo will only "
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


def send_ntfy(url, title, body, status, token=None):
    """
    POST a notification to an ntfy topic URL.
    Optionally authenticates with a Bearer token for self-hosted instances.
    Failures are printed as warnings but never raise — a notification failure
    must never abort the main script.
    """
    headers = {
        'Title':        title,
        'Priority':     _NTFY_PRIORITY[status],
        'Tags':         _NTFY_TAGS[status],
        'Content-Type': 'text/plain; charset=utf-8',
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        requests.post(
            url,
            headers=headers,
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


def process_state(domain, results_by_key, state, ntfy_url, now, ntfy_token=None):
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
                        token=ntfy_token,
                    )
                sent.append(
                    f"Recovery: {label} "
                    f"({_STATUS_COLOUR[prev_status]} → green)"
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
                token=ntfy_token,
            )
            sent.append(
                f"Degradation alert: {label} "
                f"(green → {colour_label}, {new_consecutive} consecutive runs)"
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


# Inline CSS for the self-contained HTML report. Light + dark themes via
# prefers-color-scheme; no external stylesheet, fonts, or scripts required.
_HTML_STYLE = """
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: #f9fafb;
  color: #111827;
  margin: 0;
  padding: 2rem 1rem;
  line-height: 1.5;
}
.wrap { max-width: 960px; margin: 0 auto; }
.hdr { margin-bottom: 1.5rem; }
.hdr h1 { font-size: 1.6rem; margin: 0 0 0.25rem 0; font-weight: 700; }
.hdr .domain { font-size: 1.1rem; color: #4b5563; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.hdr .meta { font-size: 0.85rem; color: #6b7280; margin-top: 0.25rem; }
.posture {
  padding: 0.85rem 1rem;
  border-radius: 8px;
  border: 1px solid;
  margin-bottom: 1rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
  font-weight: 600;
}
.posture-ok      { background:#f0fdf4; border-color:#16a34a; color:#14532d; }
.posture-warn    { background:#fffbeb; border-color:#d97706; color:#78350f; }
.posture-missing { background:#fef2f2; border-color:#dc2626; color:#7f1d1d; }
.posture-counts { font-weight: 500; font-size: 0.9rem; opacity: 0.85; }
.legend {
  display: flex; gap: 1rem; flex-wrap: wrap;
  font-size: 0.85rem; color: #6b7280;
  margin-bottom: 1.5rem;
}
.legend-item { display: flex; align-items: center; gap: 0.4rem; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.dot-ok      { background: #16a34a; }
.dot-warn    { background: #d97706; }
.dot-missing { background: #dc2626; }
.card {
  border: 1px solid;
  border-radius: 8px;
  padding: 1rem 1.25rem;
  margin-bottom: 1rem;
}
.card-ok      { background:#f0fdf4; border-color:#16a34a; }
.card-warn    { background:#fffbeb; border-color:#d97706; }
.card-missing { background:#fef2f2; border-color:#dc2626; }
.card-header {
  display: flex; justify-content: space-between;
  align-items: center; flex-wrap: wrap; gap: 0.5rem;
  margin-bottom: 0.5rem;
}
.card-label { font-weight: 700; font-size: 1.05rem; }
.badge {
  font-size: 0.8rem; font-weight: 600;
  padding: 0.2rem 0.6rem; border-radius: 12px;
  display: inline-block; white-space: nowrap;
}
.badge-ok      { background:#dcfce7; color:#15803d; }
.badge-warn    { background:#fef3c7; color:#b45309; }
.badge-missing { background:#fee2e2; color:#b91c1c; }
.summary { margin: 0.25rem 0 0.75rem 0; font-size: 0.95rem; }
.summary-ok      { color:#14532d; }
.summary-warn    { color:#78350f; }
.summary-missing { color:#7f1d1d; }
.records {
  list-style: none; padding: 0; margin: 0 0 0.5rem 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.85rem; color: #374151;
}
.records li {
  padding: 0.15rem 0;
  word-break: break-word;
}
.records li::before { content: "→ "; opacity: 0.5; }
.fix-box {
  margin-top: 0.75rem;
  padding: 0.75rem 1rem;
  background: rgba(255,255,255,0.6);
  border-radius: 6px;
  border-left: 3px solid #0891b2;
}
.fix-title {
  font-size: 0.75rem; font-weight: 700;
  letter-spacing: 0.05em; color: #0e7490;
  margin-bottom: 0.4rem;
}
.fix-list {
  list-style: disc; padding-left: 1.25rem; margin: 0;
  font-size: 0.85rem; color: #374151;
}
.fix-list li { padding: 0.15rem 0; white-space: pre-wrap; }
.footer {
  text-align: center; color: #9ca3af;
  font-size: 0.8rem; margin-top: 1.5rem;
}
.footer a { color: #6b7280; text-decoration: none; }

@media (prefers-color-scheme: dark) {
  body { background: #0b1220; color: #e5e7eb; }
  .hdr .domain { color: #9ca3af; }
  .hdr .meta { color: #6b7280; }
  .records { color: #d1d5db; }
  .summary-ok      { color:#bbf7d0; }
  .summary-warn    { color:#fde68a; }
  .summary-missing { color:#fecaca; }
  .card-ok      { background:#062013; border-color:#16a34a; }
  .card-warn    { background:#201804; border-color:#d97706; }
  .card-missing { background:#220a0a; border-color:#dc2626; }
  .posture-ok      { background:#062013; border-color:#16a34a; color:#bbf7d0; }
  .posture-warn    { background:#201804; border-color:#d97706; color:#fde68a; }
  .posture-missing { background:#220a0a; border-color:#dc2626; color:#fecaca; }
  .fix-box { background: rgba(255,255,255,0.04); }
  .fix-list { color: #d1d5db; }
  .footer, .footer a { color: #6b7280; }
}
"""


def generate_html_report(domain, results):
    """
    results: list of (label, records, status, summary, suggestions)
    Returns a self-contained HTML document with all CSS inlined. No external
    resources, scripts, or PHP. Open directly in a browser or serve as static
    content.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    statuses = [r[2] for r in results]
    n_pass = sum(1 for s in statuses if s == 'ok')
    n_warn = sum(1 for s in statuses if s == 'warn')
    n_fail = sum(1 for s in statuses if s == 'missing')

    if n_fail == 0 and n_warn == 0:
        posture_status = 'ok'
        posture_msg    = 'All checks passed'
    elif n_fail > 0:
        posture_status = 'missing'
        posture_msg    = f'{n_fail} critical issue(s) found, {n_warn} warning(s)'
    else:
        posture_status = 'warn'
        posture_msg    = f'{n_warn} warning(s) — no critical issues'

    cards = []
    for label, records, status, summary, suggestions in results:
        sym = _STATUS_SYMBOL[status]
        lbl = _STATUS_LABEL[status]

        items_html = "\n      ".join(
            f"<li>{html_lib.escape(str(r))}</li>" for r in records
        )

        if suggestions:
            fix_items = "\n        ".join(
                f"<li>{html_lib.escape(str(s))}</li>" for s in suggestions
            )
            fix_box = (
                '\n    <div class="fix-box">'
                '\n      <div class="fix-title">HOW TO FIX</div>'
                '\n      <ul class="fix-list">'
                f'\n        {fix_items}'
                '\n      </ul>'
                '\n    </div>'
            )
        else:
            fix_box = ''

        cards.append(
            f"""  <div class="card card-{status}">
    <div class="card-header">
      <span class="card-label">{html_lib.escape(label)}</span>
      <span class="badge badge-{status}">{sym} {lbl}</span>
    </div>
    <p class="summary summary-{status}">{html_lib.escape(summary)}</p>
    <ul class="records">
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
  <title>DNS Email Security Report — {html_lib.escape(domain)}</title>
  <style>{_HTML_STYLE}</style>
</head>
<body>
<div class="wrap">

  <div class="hdr">
    <h1>DNS Email Security Report</h1>
    <div class="domain">{html_lib.escape(domain)}</div>
    <div class="meta">Generated {timestamp}</div>
  </div>

  <div class="posture posture-{posture_status}">
    <span>Overall posture: {html_lib.escape(posture_msg)}</span>
    <span class="posture-counts">{n_pass} pass &nbsp;/&nbsp; {n_warn} warn &nbsp;/&nbsp; {n_fail} fail</span>
  </div>

  <div class="legend">
    <div class="legend-item"><span class="legend-dot dot-ok"></span>Pass &mdash; correctly configured</div>
    <div class="legend-item"><span class="legend-dot dot-warn"></span>Warning &mdash; present but suboptimal</div>
    <div class="legend-item"><span class="legend-dot dot-missing"></span>Fail &mdash; missing or critically misconfigured</div>
  </div>

{cards_str}

  <div class="footer">
    Generated by <a href="https://github.com/alan-berger/dnstoolbox">check_dns</a>
    &mdash; MX &middot; SPF &middot; DKIM &middot; DMARC &middot; MTA-STS &middot; DNSSEC &middot; DANE &middot; CAA &middot; BIMI
  </div>

</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_selectors(value):
    """Parse a comma-separated DKIM selector list from the CLI."""
    selectors = tuple(s.strip() for s in value.split(',') if s.strip())
    if not selectors:
        raise argparse.ArgumentTypeError(
            "At least one DKIM selector must be provided."
        )
    return selectors


def _parse_cas(value):
    """Parse a comma-separated CA domain list from the CLI."""
    cas = [s.strip().lower() for s in value.split(',') if s.strip()]
    if not cas:
        raise argparse.ArgumentTypeError(
            "At least one CA domain must be provided."
        )
    return cas


def main():
    default_state_file = str(Path(__file__).parent / 'check_dns_state.json')

    parser = argparse.ArgumentParser(
        description=(
            "Audit email-related DNS records and security policies for a domain. "
            "Checks MX, SPF, DKIM, DMARC, MTA-STS, DNSSEC, DANE, CAA, and BIMI."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s example.com\n"
            "  %(prog)s example.com --html > report.html\n"
            "  %(prog)s example.com --dkim-selectors google,selector1,selector2\n"
            "  %(prog)s example.com --permitted-cas letsencrypt.org,sectigo.com\n"
            "  %(prog)s example.com --ntfy-url https://ntfy.sh/your-topic\n"
            "  %(prog)s example.com --html --ntfy-url https://ntfy.sh/your-topic \\\n"
            "      --audit-log /var/log/dns_audit.jsonl \\\n"
            "      --healthcheck-url https://hc-ping.com/your-uuid \\\n"
            "      > /var/www/html/dns-report.html\n"
        ),
    )
    parser.add_argument(
        "domain", nargs="?",
        help="Domain name to check (prompts interactively if omitted)",
    )
    parser.add_argument(
        "--html", action="store_true",
        help=(
            "Output a self-contained HTML report instead of terminal output. "
            "Pipe to a file: check_dns.py example.com --html > report.html"
        ),
    )
    parser.add_argument(
        "--dkim-selectors", type=_parse_selectors, default=DEFAULT_DKIM_SELECTORS,
        metavar="LIST",
        help=(
            "Comma-separated list of DKIM selectors to probe. "
            f"Default: {','.join(DEFAULT_DKIM_SELECTORS)}. "
            "Find your selector by inspecting the s= tag in a DKIM-Signature: header."
        ),
    )
    parser.add_argument(
        "--permitted-cas", type=_parse_cas, default=['letsencrypt.org'],
        metavar="LIST",
        help=(
            "Comma-separated list of CA domains permitted in CAA records. "
            "Default: letsencrypt.org"
        ),
    )
    parser.add_argument(
        "--state-file", default=default_state_file, metavar="PATH",
        help=(
            "Path to the JSON state file used to detect status regressions. "
            "Defaults to check_dns_state.json in the script directory. "
            "Created automatically on first run."
        ),
    )
    parser.add_argument(
        "--audit-log", default=None, metavar="PATH",
        help=(
            "Path to an append-only JSON Lines audit log recording the result "
            "of every check on every run. Optional."
        ),
    )
    parser.add_argument(
        "--ntfy-url", default=None, metavar="URL",
        help=(
            "ntfy topic URL to receive push notifications when a "
            "delivery-critical check (MX, SPF, DKIM, DMARC, MTA-STS, DNSSEC, DANE, CAA) "
            "degrades from green to amber/red (confirmed over 2 consecutive runs), or "
            "recovers back to green. "
            "Example: https://ntfy.sh/your-topic"
        ),
    )
    parser.add_argument(
        "--ntfy-token", default=None, metavar="TOKEN",
        help=(
            "Bearer token for authenticating to a self-hosted ntfy instance. "
            "Not required for the public ntfy.sh service."
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

    args       = parser.parse_args()
    raw_domain = args.domain or input("Enter domain to check: ").strip()
    try:
        domain = validate_domain(raw_domain)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    dkim_selectors = args.dkim_selectors
    dkim_label     = f"DKIM Record (selectors: {', '.join(dkim_selectors)})"

    # Each entry: (display_label, state_key, check_function)
    checks = [
        ("MX Records",     "mx",      lambda d: check_mx(d)),
        ("SPF Record",     "spf",     lambda d: check_spf(d)),
        (dkim_label,       "dkim",    lambda d: check_dkim(d, selectors=dkim_selectors)),
        ("DMARC Record",   "dmarc",   lambda d: check_dmarc(d)),
        ("MTA-STS Record", "mta_sts", lambda d: check_mta_sts(d)),
        ("DNSSEC",         "dnssec",  lambda d: check_dnssec(d)),
        ("DANE Record",    "dane",    lambda d: check_dane(d)),
        ("CAA Record",     "caa",     lambda d: check_caa(d, permitted_cas=args.permitted_cas)),
        ("BIMI Record",    "bimi",    lambda d: check_bimi(d)),
    ]

    # Run all checks
    results_by_key = {}
    for label, key, check_func in checks:
        records, status, summary, suggestions = check_func(domain)
        results_by_key[key] = (label, records, status, summary, suggestions)

    now = datetime.now(timezone.utc).isoformat(timespec='seconds')

    # State tracking and notifications
    state         = load_state(args.state_file, domain)
    notifications = process_state(
        domain, results_by_key, state, args.ntfy_url, now,
        ntfy_token=args.ntfy_token,
    )
    state['last_run'] = now
    save_state(args.state_file, state)

    # Audit log
    if args.audit_log:
        append_audit_log(args.audit_log, domain, now, results_by_key)

    # Dead man's switch
    if args.healthcheck_url:
        ping_healthcheck(args.healthcheck_url)

    # Build ordered list for renderers
    gathered = [results_by_key[key] for _, key, _ in checks]

    if args.html:
        print(generate_html_report(domain, gathered))
    else:
        sep = "\u2500" * 52
        print(f"\n{sep}")
        print(f"  DNS Email Security Report — {domain}")
        print(sep)
        for label, records, status, summary, suggestions in gathered:
            print_terminal_result(label, records, status, summary, suggestions)
        if notifications:
            print(f"\n{CYAN}  Notifications sent this run:{RESET}")
            for note in notifications:
                print(f"  {CYAN}  → {note}{RESET}")
        print()


if __name__ == "__main__":
    main()
