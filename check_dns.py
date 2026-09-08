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
import smtplib
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


def _certificate_to_der(cert):
    """
    Convert one entry from a peer certificate chain to DER bytes.

    The object returned by get_unverified_chain() has varied across Python
    versions — DER encoding constant, PEM string, or raw bytes — so each shape is
    tried in turn rather than assuming one. Returns (der_bytes, error).
    """
    if isinstance(cert, bytes):
        return cert, None

    public_bytes = getattr(cert, 'public_bytes', None)
    if public_bytes is not None:
        for encoding in (getattr(ssl, 'ENCODING_DER', None),
                         getattr(getattr(ssl, '_ssl', None), 'ENCODING_DER', None)):
            if encoding is None:
                continue
            try:
                return public_bytes(encoding), None
            except Exception:
                continue
        try:
            pem = public_bytes(getattr(ssl, 'ENCODING_PEM', 1))
            if isinstance(pem, bytes):
                pem = pem.decode('ascii', 'replace')
            return ssl.PEM_cert_to_DER_cert(pem), None
        except Exception as exc:
            return None, f"could not encode a chain certificate: {exc}"

    return None, f"unrecognised certificate object of type {type(cert).__name__}"


def _peer_certificate_chain(sock):
    """
    Return (chain_ders, note) for the certificate chain the peer presented.

    Needed for DANE-TA (usage 2) records, which pin a trust anchor somewhere in
    the chain rather than the end-entity certificate. On failure the chain is
    empty and 'note' explains why, so the report can say what stopped the check
    instead of leaving the reader guessing. DANE-TA records then grade as
    unverified rather than failed.

    SSLSocket.get_unverified_chain() is public from Python 3.13. Earlier versions
    expose the same call on the private _sslobj, which is used as a fallback
    because the alternative is silently downgrading every DANE-TA deployment to
    unverifiable.
    """
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    getter = getattr(sock, 'get_unverified_chain', None)
    source = "SSLSocket.get_unverified_chain()"
    if getter is None:
        sslobj = getattr(sock, '_sslobj', None)
        getter = getattr(sslobj, 'get_unverified_chain', None)
        source = "_sslobj.get_unverified_chain()"

    if getter is None:
        return [], (
            f"Python {version} exposes no peer certificate chain accessor "
            "(3.13 or later does)"
        )

    try:
        certs = getter()
    except Exception as exc:
        return [], f"{source} failed on Python {version}: {exc}"

    if not certs:
        return [], f"{source} returned no certificates"

    ders   = []
    errors = []
    for cert in certs:
        der, error = _certificate_to_der(cert)
        if der:
            ders.append(der)
        elif error:
            errors.append(error)

    if not ders:
        return [], (
            f"{source} returned {len(certs)} certificate(s) that could not be "
            f"decoded on Python {version}: {errors[0] if errors else 'unknown reason'}"
        )
    return ders, None


def _fetch_smtp_certificate(hostname, port=25, timeout=10):
    """
    Connect to an SMTP server and retrieve the TLS certificate it presents.

    Returns (cert_der_bytes, None) on success or (None, error_str) on failure.

    Uses smtplib rather than a hand-rolled dialogue. RFC 5321 requires EHLO
    before STARTTLS — Exchange Online answers a bare STARTTLS with
    '503 5.5.2 Send hello first' — and banners and EHLO responses are multi-line,
    so a single recv() is not guaranteed to frame a whole response. Getting
    either wrong produces a spurious "certificate could not be retrieved" on
    servers that are configured correctly.

    Certificate verification is deliberately disabled. DANE-EE (usage 3) pins
    the certificate itself and is routinely used with certificates that do not
    chain to a public root, so PKIX validation here would reject valid DANE
    deployments. The certificate is being fetched to hash it, not to make a
    trust decision.
    """
    smtp = None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        # The hostname must go to the constructor, not to a later connect():
        # smtplib takes the SNI name for STARTTLS from the value stored there,
        # and providers may serve a different certificate per SNI name.
        smtp = smtplib.SMTP(hostname, port, timeout=timeout)

        code, _ = smtp.ehlo()
        if code >= 400:
            code, _ = smtp.helo()
            if code >= 400:
                return None, [], None, f"{hostname}:{port} rejected EHLO and HELO (code {code})"

        if not smtp.has_extn('starttls'):
            return None, [], None, (
                f"{hostname}:{port} does not advertise STARTTLS, so it cannot serve a "
                "certificate"
            )

        smtp.starttls(context=context)

        sock = getattr(smtp, 'sock', None)
        if sock is None or not isinstance(sock, ssl.SSLSocket):
            return None, [], None, f"{hostname}:{port} accepted STARTTLS but did not negotiate TLS"

        cert_der = sock.getpeercert(binary_form=True)
        if not cert_der:
            return None, [], None, (
                f"{hostname}:{port} negotiated TLS but presented no certificate"
            )
        chain_ders, chain_note = _peer_certificate_chain(sock)
        return cert_der, chain_ders, chain_note, None

    except socket.timeout:
        return None, [], None, (
            f"connection to {hostname}:{port} timed out after {timeout}s — many "
            "networks and cloud providers block outbound port 25"
        )
    except socket.gaierror as exc:
        return None, [], None, f"failed to resolve {hostname}: {exc}"
    except ssl.SSLError as exc:
        return None, [], None, f"TLS handshake with {hostname}:{port} failed: {exc}"
    except smtplib.SMTPResponseException as exc:
        detail = exc.smtp_error
        if isinstance(detail, bytes):
            detail = detail.decode('utf-8', 'replace')
        return None, [], None, (
            f"{hostname}:{port} refused STARTTLS (code {exc.smtp_code}: "
            f"{str(detail)[:120]})"
        )
    except smtplib.SMTPException as exc:
        return None, [], None, f"SMTP error talking to {hostname}:{port}: {exc}"
    except OSError as exc:
        return None, [], None, (
            f"could not connect to {hostname}:{port}: {exc} — outbound port 25 may be "
            "blocked on this host"
        )
    except Exception as exc:
        return None, [], None, f"error fetching certificate from {hostname}:{port}: {exc}"
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass


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
# DANE (RFC 6698, RFC 7672)
#
# Two facts drive the design of this section:
#
#   1. A TLSA record lives in the zone of the MX *hostname*, not in the zone of
#      the mail domain. When inbound mail is handled by a hosted provider
#      (Microsoft 365, Google Workspace, a filtering gateway) the domain owner
#      cannot publish that record at all, so generic "add a TLSA record" advice
#      is wrong and unactionable.
#
#   2. DANE applies per MX host, not per domain (RFC 7672 §2.2). A sender may
#      select any MX; if the one it picks has no TLSA record, it falls back to
#      opportunistic TLS for that delivery. Partial coverage therefore protects
#      nothing reliably, so every MX host is checked, not just the primary.
#
# The provider table supplies names and vendor-specific procedures only.
# Whether DANE is *possible* is decided at runtime from evidence: the zone cut
# containing each MX host is located and probed for DNSKEY. A stale table
# therefore degrades to correct-but-generic guidance rather than to confidently
# wrong instructions.
# ---------------------------------------------------------------------------

# 'inbound_dane' values — what, if anything, the domain owner can do:
#
#   'customer'  — the provider offers inbound DANE and a customer action turns
#                 it on. Graded FAIL when absent: it is actionable.
#   'migration' — the provider offers it, but only on a different MX endpoint;
#                 the fix is to move. Graded FAIL: also actionable.
#   'provider'  — the provider publishes TLSA records itself and there is
#                 nothing to configure. Absence is anomalous rather than a
#                 misconfiguration of this domain.
#   'no'        — the provider does not offer inbound DANE; no action exists.
#   'unknown'   — not established. The runtime DNSSEC probe decides, and the
#                 output stays accurate as vendors change their offerings.
#
# Only 'customer', 'migration', 'provider' and 'no' make a claim about a
# vendor. Entries marked 'unknown' are present purely so the report can name
# the provider — that is useful on its own and cannot go stale.
#
# Guidance strings are formatted with {domain}, {mx} and {apex}.
_MAIL_PROVIDERS = (
    {
        'name': 'Microsoft 365 / Exchange Online (DNSSEC-enabled endpoint)',
        'suffixes': ('mx.microsoft',),
        'inbound_dane': 'customer',
        'guidance': [
            "This MX is already on Microsoft's DNSSEC-signed mail-flow endpoint, but "
            "inbound SMTP DANE has not been switched on for the domain. TLSA records "
            "here are published and rotated by Microsoft, not by you.",
            "In Exchange Online PowerShell run: Enable-SmtpDaneInbound -DomainName {domain}",
            "Allow 15-30 minutes for the TLSA records to publish, then verify with: "
            "dig TLSA _25._tcp.{mx}",
            "Exchange Online publishes several TLSA records per host and expects some "
            "of them not to match the certificate currently served; one match is "
            "sufficient.",
        ],
    },
    {
        'name': 'Microsoft 365 / Exchange Online',
        'suffixes': (
            'mail.protection.outlook.com',
            'mail.eo.outlook.com',
            'olc.protection.outlook.com',
        ),
        'inbound_dane': 'migration',
        'guidance': [
            "You cannot publish a TLSA record for this MX host. Its zone is operated by "
            "Microsoft and is not DNSSEC-signed, so DANE cannot be validated against it "
            "regardless of what you publish in {domain}.",
            "Microsoft offers inbound SMTP DANE only on its newer DNSSEC-signed endpoint "
            "under mx.microsoft. Migrating is the correct fix, in this order:",
            "1. Sign the {domain} zone with DNSSEC and publish the DS record at your "
            "registrar. Microsoft will not enable DANE until your own chain of trust is "
            "intact.",
            "2. Lower the TTL on the existing MX record (not below 30 seconds) and wait "
            "for the old TTL to expire.",
            "3. In Exchange Online PowerShell run: "
            "Enable-DnssecForVerifiedDomain -DomainName {domain} — this returns a "
            "DnssecMxValue such as example-com.o-v1.mx.microsoft (the middle label is "
            "tenant-specific and is not predictable).",
            "4. Add that value as an additional MX at a higher preference number (lower "
            "priority), test inbound delivery, then promote it to preference 0 and "
            "remove the old {mx} record.",
            "5. Run: Enable-SmtpDaneInbound -DomainName {domain}. Microsoft then "
            "publishes and rotates the TLSA records for you.",
            "Microsoft's documentation assumes a single MX at preference 0 or 10 with no "
            "fallback MX. If you keep a secondary MX, mail delivered to it is not "
            "DANE-protected.",
            "From 1 July 2026 Microsoft provisions new accepted domains under "
            "*.mx.microsoft automatically; existing domains still require the migration "
            "above.",
            "onmicrosoft.com tenant domains and self-service sign-up domains are not "
            "supported for inbound SMTP DANE.",
            "If a filtering gateway (Mimecast, Proofpoint, Barracuda and similar) sits in "
            "front of Exchange Online, the last SMTP hop is theirs, not Microsoft's — "
            "DANE then depends entirely on that vendor.",
            "Until the migration is done, MTA-STS is the transport-security control you "
            "can deploy yourself for this domain.",
        ],
    },
    {
        'name': 'Google Workspace / Gmail',
        'suffixes': (
            'aspmx.l.google.com',
            'l.google.com',
            'googlemail.com',
            'smtp.google.com',
        ),
        'inbound_dane': 'no',
        'guidance': [
            "You cannot publish a TLSA record for this MX host — the zone belongs to "
            "Google, and a TLSA record placed in the {domain} zone has no effect.",
            "Google validates DANE on mail it sends, but does not publish TLSA records "
            "for inbound Workspace mail and does not sign these zones with DNSSEC. "
            "There is no tenant setting that changes this, so no action is available to "
            "you here.",
            "Deploy MTA-STS in enforce mode and TLS-RPT instead — both are published in "
            "your own zone, are supported by Google, and give you downgrade protection "
            "plus failure reporting.",
        ],
    },
    {
        # Proton publishes TLSA records on its MX hosts and states that this
        # covers the custom domains it hosts. Verified by observation of
        # _25._tcp.mail.protonmail.ch.
        'name': 'Proton Mail',
        'suffixes': ('protonmail.ch', 'protonmail.com', 'proton.me'),
        'inbound_dane': 'provider',
        'guidance': [
            "Proton publishes and rotates the TLSA records for its own MX hosts, which "
            "covers the custom domains it hosts. There is nothing to configure in the "
            "{domain} zone.",
            "No TLSA record was found for this host, which is unexpected. Confirm the MX "
            "hostname is correct and current before raising it with Proton.",
            "Signing the {domain} zone with DNSSEC is still worthwhile: it protects the "
            "MX lookup itself, without which a sender cannot trust which host to apply "
            "DANE to.",
        ],
    },
    {
        # Reported to publish TLSA records; not independently verified here, so
        # the wording below stays hedged.
        'name': 'Fastmail',
        'suffixes': ('messagingengine.com',),
        'inbound_dane': 'provider',
        'guidance': [
            "Fastmail is understood to publish TLSA records for its inbound MX hosts, so "
            "there is normally nothing to configure in the {domain} zone.",
            "No TLSA record was found for this host. Confirm the MX hostname matches "
            "Fastmail's current documentation — regional MX hosts differ — and check "
            "with them if it does.",
            "Signing the {domain} zone with DNSSEC is still worthwhile: it protects the "
            "MX lookup itself.",
        ],
    },
    # The entries below exist so the report can name the provider. Their
    # inbound-DANE posture is not asserted; the runtime DNSSEC probe decides.
    {
        'name': 'Proofpoint',
        'suffixes': ('pphosted.com', 'ppe-hosted.com', 'proofpoint.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Mimecast',
        'suffixes': ('mimecast.com', 'mimecast.co.za', 'mimecast-offshore.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Barracuda Email Security Service',
        'suffixes': ('barracudanetworks.com', 'barracuda.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Cisco Secure Email (IronPort)',
        'suffixes': ('iphmx.com', 'cisco.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Zoho Mail',
        'suffixes': ('zoho.com', 'zoho.eu', 'zoho.in', 'zohomail.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Amazon SES / WorkMail',
        'suffixes': ('amazonaws.com', 'awsapps.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Cloudflare Email Routing',
        'suffixes': ('mx.cloudflare.net',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Apple iCloud Mail',
        'suffixes': ('mail.icloud.com', 'icloud.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'mailbox.org',
        'suffixes': ('mailbox.org',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Posteo',
        'suffixes': ('posteo.de',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Migadu',
        'suffixes': ('migadu.com',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Tuta (Tutanota)',
        'suffixes': ('tutanota.de', 'tuta.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Rackspace Email',
        'suffixes': ('emailsrvr.com',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'GoDaddy / Secureserver',
        'suffixes': ('secureserver.net',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Namecheap Private Email',
        'suffixes': ('privateemail.com',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Titan Mail',
        'suffixes': ('titan.email',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'Hostinger Email',
        'suffixes': ('hostinger.com',),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'OVHcloud',
        'suffixes': ('ovh.net', 'ovh.ca'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
    {
        'name': 'IONOS',
        'suffixes': ('ionos.com', 'ionos.de', 'kundenserver.de', 'ui-dns.com'),
        'inbound_dane': 'unknown',
        'guidance': [],
    },
)

# MX endpoints that still route mail but are superseded — flagged separately
# because they usually indicate a stale DNS zone rather than a deliberate choice.
_LEGACY_MX_SUFFIXES = {
    'mail.eo.outlook.com': (
        "legacy Exchange Online (FOPE-era) endpoint. Microsoft has recommended the "
        "current *.mail.protection.outlook.com endpoint for years, and this one is a "
        "dead end for DANE."
    ),
}

# Worst-first ordering used when reducing per-host statuses to one overall status.
_STATUS_SEVERITY = {'missing': 2, 'warn': 1, 'ok': 0}


def _match_mail_provider(mx_hostname):
    """Return (provider_dict, matched_suffix), or (None, None) if unrecognised."""
    host = mx_hostname.rstrip('.').lower()
    for provider in _MAIL_PROVIDERS:
        for suffix in provider['suffixes']:
            if host == suffix or host.endswith('.' + suffix):
                return provider, suffix
    return None, None


def _mx_is_self_hosted(domain, mx_hostname):
    """
    True when the MX hostname sits inside the checked domain's own namespace,
    i.e. the operator plausibly controls the zone the TLSA record must live in.

    Deliberately conservative: an MX under a different domain you also own
    (example.com -> mail.example.net) is reported as third-party. That case is
    handled by the --dane-self-hosted override rather than by guessing.
    """
    host   = mx_hostname.rstrip('.').lower()
    domain = domain.rstrip('.').lower()
    return host == domain or host.endswith('.' + domain)


def _zone_apex(name):
    """
    Return the apex of the zone that actually contains 'name', or None if it
    cannot be determined.

    Queries SOA for the name itself: an authoritative NODATA response carries the
    containing zone's SOA in the authority section. This is more accurate than
    walking labels upward, which would find the signed TLD above an unsigned
    provider zone and report a false positive.
    """
    try:
        answer = _resolver.resolve(name, 'SOA', raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.resolver.NoAnswer, dns.exception.Timeout):
        return None

    if answer.rrset is not None:
        return answer.rrset.name.to_text().rstrip('.').lower()
    for rrset in answer.response.authority:
        if rrset.rdtype == dns.rdatatype.SOA:
            return rrset.name.to_text().rstrip('.').lower()
    return None


def _zone_is_dnssec_signed(zone):
    """
    True / False / None (undetermined) for whether 'zone' publishes DNSKEY.

    Structural check only, matching check_dnssec(): it does not validate the
    chain of trust to the root. None is returned on transport failures so a
    timeout is never reported as 'unsigned'.
    """
    try:
        answer = _resolver.resolve(zone, 'DNSKEY', raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except (dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    return answer.rrset is not None and len(answer.rrset) > 0


def _sorted_mx_hosts(domain):
    """
    Return (preference, hostname) pairs ordered by preference, lowest first.

    get_dns_records() returns 'preference hostname' strings in resolver order,
    which is not preference order.
    """
    parsed = []
    for record in get_dns_records(domain, 'MX'):
        parts = record.split()
        if len(parts) < 2:
            continue
        try:
            preference = int(parts[0])
        except ValueError:
            continue
        host = parts[1].rstrip('.').lower()
        if host and host != '.':          # null MX (RFC 7505) has no host
            parsed.append((preference, host))
    parsed.sort(key=lambda item: (item[0], item[1]))
    return parsed


def _format_guidance(lines, domain, mx_hostname, apex):
    return [
        line.format(domain=domain, mx=mx_hostname, apex=apex or 'the MX hostname')
        for line in lines
    ]


def _dedupe(items):
    """Remove duplicates while preserving first-seen order."""
    seen = set()
    out  = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# TLSA record handling
# ---------------------------------------------------------------------------

_TLSA_USAGE_MAP    = {'0': 'PKIX-TA', '1': 'PKIX-EE', '2': 'DANE-TA', '3': 'DANE-EE'}
_TLSA_SELECTOR_MAP = {'0': 'Full Cert', '1': 'Public Key'}
_TLSA_TYPE_MAP     = {'1': 'SHA-256', '2': 'SHA-512'}


def _parse_tlsa_record(record):
    """
    Parse one TLSA record into (usage, selector, matching_type, hash, error).

    dnspython renders the certificate association data with embedded whitespace
    for long hashes, so everything from field four onward is joined and stripped
    rather than taking a single token.
    """
    parts = record.split()
    if len(parts) < 4:
        return None, None, None, None, f"malformed TLSA record: {record}"

    usage, selector, matching_type = parts[0], parts[1], parts[2]
    tlsa_hash = ''.join(parts[3:]).lower()

    if usage not in _TLSA_USAGE_MAP:
        return None, None, None, None, (
            f"invalid usage field '{usage}' (expected 0-3; RFC 7672 recommends 3, DANE-EE)"
        )
    if selector not in _TLSA_SELECTOR_MAP:
        return None, None, None, None, (
            f"invalid selector field '{selector}' (expected 0 or 1; 1 is recommended)"
        )
    if matching_type not in _TLSA_TYPE_MAP:
        return None, None, None, None, (
            f"invalid matching-type field '{matching_type}' (expected 1 or 2; "
            "1 is SHA-256)"
        )
    return usage, selector, matching_type, tlsa_hash, None


def _cert_association_hash(cert_der, selector, matching_type):
    """
    Compute the certificate association data a TLSA record should contain for
    this certificate, for the given selector and matching type.

    Returns (hex_digest, error). Import errors are surfaced to the caller rather
    than raised so the check can degrade to a warning.
    """
    try:
        import hashlib
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None, "the 'cryptography' library is not installed"

    try:
        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
        if selector == '1':
            data = cert_obj.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            data = cert_der

        if matching_type == '1':
            return hashlib.sha256(data).hexdigest(), None
        if matching_type == '2':
            return hashlib.sha512(data).hexdigest(), None
        return None, f"unsupported matching type '{matching_type}'"
    except Exception as exc:
        return None, f"hash computation failed: {str(exc)[:80]}"


def _validate_tlsa_set(host, tlsa_records, cert_der, chain_ders, chain_note=None):
    """
    Validate every TLSA record at a host against what the server presented.

    Three rules from RFC 7671/7672 drive this, and getting any of them wrong
    produces false failures on correctly configured hosts:

      - A host's TLSA records are a set of alternatives. The connection is
        authenticated if ANY usable record matches (RFC 7672 §2.2), so providers
        that rotate keys publish several and expect some not to match.

      - Usage 3 (DANE-EE) pins the end-entity certificate; usage 2 (DANE-TA)
        pins a trust anchor somewhere in the presented chain. Comparing a
        DANE-TA record against the leaf certificate is simply the wrong
        comparison and will never match.

      - Usage 0 (PKIX-TA) and 1 (PKIX-EE) MUST be ignored by SMTP clients
        (RFC 7672 §3.1.3), so they are reported and excluded rather than tested.

    Returns (status, lines, suggestions, reason).
    """
    lines       = []
    suggestions = []
    matched     = 0
    comparable  = 0
    unverified  = 0
    ignored     = 0

    for record in tlsa_records:
        usage, selector, matching_type, tlsa_hash, error = _parse_tlsa_record(record)
        if error:
            lines.append(f"TLSA: {error}")
            continue

        descriptor = (
            f"usage={_TLSA_USAGE_MAP[usage]}, "
            f"selector={_TLSA_SELECTOR_MAP[selector]}, "
            f"type={_TLSA_TYPE_MAP[matching_type]}"
        )

        # PKIX-TA / PKIX-EE: not usable for SMTP.
        if usage in ('0', '1'):
            ignored += 1
            lines.append(
                f"TLSA [{descriptor}]: ignored — RFC 7672 requires SMTP clients to "
                "disregard PKIX-TA and PKIX-EE records"
            )
            continue

        # DANE-TA: the anchor may be any certificate in the presented chain.
        if usage == '2':
            if not chain_ders:
                unverified += 1
                lines.append(
                    f"TLSA [{descriptor}]: trust-anchor record, not verified — "
                    + (chain_note or "the certificate chain could not be read")
                )
                continue
            comparable += 1
            hit = False
            for candidate in chain_ders:
                computed, comp_error = _cert_association_hash(
                    candidate, selector, matching_type)
                if comp_error:
                    continue
                if computed == tlsa_hash:
                    hit = True
                    break
            if hit:
                matched += 1
                lines.append(
                    f"TLSA [{descriptor}]: matches a certificate in the served chain"
                )
            else:
                lines.append(
                    f"TLSA [{descriptor}]: no certificate in the served chain "
                    f"({len(chain_ders)} presented) matches"
                )
            continue

        # DANE-EE: pins the end-entity certificate.
        computed, comp_error = _cert_association_hash(cert_der, selector, matching_type)
        if comp_error:
            unverified += 1
            lines.append(f"TLSA [{descriptor}]: could not verify — {comp_error}")
            continue

        comparable += 1
        if computed == tlsa_hash:
            matched += 1
            lines.append(f"TLSA [{descriptor}]: matches the served certificate")
        else:
            lines.append(
                f"TLSA [{descriptor}]: does not match (DNS {tlsa_hash[:16]}…, "
                f"cert {computed[:16]}…)"
            )

    total_notes = []
    if ignored:
        total_notes.append(f"{ignored} ignored as PKIX")
    if unverified:
        total_notes.append(f"{unverified} not verifiable")
    suffix = f" ({', '.join(total_notes)})" if total_notes else ""

    if matched:
        lines.append(
            f"{matched} of {comparable} verifiable TLSA record(s) match{suffix} — "
            "one match is sufficient"
        )
        return 'ok', lines, suggestions, "DANE valid"

    if unverified and not comparable:
        suggestions.append(
            "This host publishes only trust-anchor (DANE-TA) records and the "
            "certificate chain could not be read, so the pinning could not be "
            "confirmed. Python 3.13 or later exposes the chain directly; on older "
            "versions verify manually: openssl s_client -showcerts -connect "
            f"{host}:25 -starttls smtp"
        )
        return ('warn', lines, suggestions,
                "TLSA published but could not be verified from this connection")

    if not comparable:
        return ('missing', lines, [
            "No TLSA record at this host is usable for SMTP. RFC 7672 requires usage 2 "
            "(DANE-TA) or usage 3 (DANE-EE); usage 0 and 1 records are ignored by "
            "sending servers.",
            "Republish as usage 3 with selector 1 and matching type 1 (3 1 1), which is "
            "the recommended combination for SMTP.",
        ], "no TLSA record usable for SMTP")

    suggestions.append(
        f"None of the {comparable} verifiable TLSA record(s) at this host match what it "
        f"is serving{suffix}, so every DANE-enforcing sender will refuse delivery."
    )
    suggestions.append(
        f"If the certificate was renewed, republish the TLSA record: "
        f"echo | openssl s_client -connect {host}:25 -starttls smtp 2>/dev/null | "
        "openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | "
        "openssl dgst -sha256 -hex | cut -d' ' -f2"
    )
    suggestions.append(
        "Publish the new record alongside the old one before the certificate changes, "
        "and remove the old one only after the TTL has expired — that is the rotation "
        "order that avoids an outage."
    )
    return ('missing', lines, suggestions,
            "TLSA records do not match what the server presents")


# ---------------------------------------------------------------------------
# Per-host evaluation
# ---------------------------------------------------------------------------

def _dane_self_hosted_absent(domain, host, apex, apex_signed):
    """Remediation for an MX with no TLSA record, in a zone the operator controls."""
    tlsa_name   = f"_25._tcp.{host}"
    suggestions = [
        f"Add a TLSA record at {tlsa_name} with format:",
        f"_25._tcp.{host}.  3600  IN  TLSA  3 1 1 <sha256-hash>",
        "The hash is the SHA-256 of the mail server's public key (TLSA 3 1 1).",
        f"Generate the hash: echo | openssl s_client -connect {host}:25 "
        "-starttls smtp 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey "
        "-pubin -outform DER | openssl dgst -sha256 -hex | cut -d' ' -f2",
        f"Once published, verify with: dig TLSA {tlsa_name}",
    ]

    if apex_signed is False:
        suggestions.insert(
            0,
            f"Sign the {apex} zone with DNSSEC first and publish its DS record at the "
            "parent. TLSA records in an unsigned zone are unauthenticated and are "
            "ignored by every validating sender, so DANE would have no effect.",
        )
    elif apex_signed is None:
        suggestions.append(
            f"DNSSEC status of the {apex or 'MX'} zone could not be determined on this "
            "run; confirm it is signed, as DANE provides no security without it."
        )
    else:
        suggestions.append(
            f"DANE requires DNSSEC on the zone holding the TLSA record — {apex} appears "
            "to be signed, so publishing the TLSA record is sufficient."
        )

    return 'missing', "no TLSA record published", suggestions


def _dane_third_party_absent(domain, host, provider, apex, apex_signed,
                             third_party_status):
    """
    Remediation for an MX with no TLSA record, in a zone the operator does not
    control.

    The status choice is deliberate: a missing TLSA record on a provider that
    does not offer DANE is not a misconfiguration of this domain and there is no
    action the operator can take, so it defaults to WARNING rather than FAIL.
    Where the provider does offer DANE and it has simply not been enabled, that
    is actionable and stays FAIL.
    """
    provider_name = provider['name'] if provider else None
    inbound       = provider['inbound_dane'] if provider else 'unknown'
    apex_label    = apex or 'the MX hostname'

    if provider and provider['guidance']:
        suggestions = _format_guidance(provider['guidance'], domain, host, apex)
    else:
        suggestions = [
            f"You do not control the {apex_label} zone, so there is nothing to publish "
            f"in {domain}. DANE is validated against TLSA records at the MX hostname, "
            "not at the mail domain.",
            f"Ask {provider_name or 'your mail provider'} whether they publish "
            "DNSSEC-signed TLSA records for inbound MX hosts, or whether they offer a "
            "DANE-capable endpoint you can migrate your MX to.",
            "Deploy MTA-STS in enforce mode and TLS-RPT in the meantime — both live in "
            "your own zone and give you downgrade protection you control.",
            f"If you do in fact operate {apex_label}, re-run with --dane-self-hosted to "
            "get TLSA publication steps instead.",
        ]

    if inbound == 'customer':
        return 'missing', "DANE supported by the provider but not enabled", suggestions
    if inbound == 'migration':
        return 'missing', "endpoint cannot support DANE; provider offers a migration path", suggestions
    if inbound == 'provider':
        return third_party_status, "provider normally publishes TLSA; none found", suggestions
    if inbound == 'no':
        return third_party_status, "provider does not offer inbound DANE", suggestions
    return third_party_status, "MX operated by a third party; DANE not available", suggestions


def _check_mx_host(domain, host, third_party_status, assume_self_hosted):
    """
    Evaluate DANE for a single MX host.

    Returns a dict with: host, status, has_tlsa, lines, suggestions, reason,
    provider_name, apex, apex_signed.
    """
    provider, _ = _match_mail_provider(host)
    apex        = _zone_apex(host)
    apex_signed = _zone_is_dnssec_signed(apex) if apex else None
    self_hosted = assume_self_hosted or _mx_is_self_hosted(domain, host)

    apex_label = apex or 'unknown zone'
    if apex_signed is True:
        zone_line = f"zone {apex_label}: DNSSEC-signed"
    elif apex_signed is False:
        zone_line = f"zone {apex_label}: NOT DNSSEC-signed"
    else:
        zone_line = f"zone {apex_label}: DNSSEC status undetermined"

    notes = [
        f"note: this is a {note}"
        for suffix, note in _LEGACY_MX_SUFFIXES.items()
        if host == suffix or host.endswith('.' + suffix)
    ]

    # Line fields are kept separate rather than pre-joined so that hosts with
    # identical findings — the five Google MX hosts, for example — can be
    # collapsed into one block at render time.
    info = {
        'host':          host,
        'provider_name': provider['name'] if provider else None,
        'apex':          apex,
        'apex_signed':   apex_signed,
        'self_hosted':   self_hosted,
        'zone_line':     zone_line,
        'scope_line':    None,
        'notes':         notes,
        'detail_lines':  [],
        'suggestions':   [],
    }

    tlsa_records     = get_dns_records(f"_25._tcp.{host}", 'TLSA')
    info['has_tlsa'] = bool(tlsa_records)

    # ---- No TLSA record ----------------------------------------------------
    if not tlsa_records:
        info['tlsa_line'] = "no TLSA record at _25._tcp.<host>"
        if self_hosted:
            status, reason, suggestions = _dane_self_hosted_absent(
                domain, host, apex, apex_signed)
        else:
            info['scope_line'] = (
                f"MX host is outside the {domain} zone"
                + (f" ({info['provider_name']})" if info['provider_name'] else "")
            )
            status, reason, suggestions = _dane_third_party_absent(
                domain, host, provider, apex, apex_signed, third_party_status)
        info.update(status=status, reason=reason, suggestions=suggestions)
        return info

    # ---- TLSA present: validate against the served certificate -------------
    info['tlsa_line'] = f"{len(tlsa_records)} TLSA record(s) at _25._tcp.<host>"

    cert_der, chain_ders, chain_note, cert_error = _fetch_smtp_certificate(
        host, port=25, timeout=10)
    if cert_der is None:
        info.update(
            status='warn',
            reason="TLSA published but the certificate could not be retrieved",
            suggestions=[
                f"Verify connectivity to {host}:25 — check firewall rules and SMTP "
                "service status.",
                f"Test manually: openssl s_client -connect {host}:25 -starttls smtp",
                "Until the certificate can be fetched, this script cannot confirm the "
                "TLSA record still matches.",
            ],
        )
        info['detail_lines'].append(f"certificate fetch failed: {cert_error}")
        return info

    status, lines, suggestions, reason = _validate_tlsa_set(
        host, tlsa_records, cert_der, chain_ders, chain_note)
    info['detail_lines'].extend(lines)
    info['reason'] = reason

    # A matching TLSA record in an unsigned zone is decorative: senders cannot
    # authenticate it, so it must not be graded as a pass.
    if status == 'ok' and apex_signed is False:
        status = 'warn'
        suggestions = [
            f"The TLSA record matches the served certificate, but {apex_label} is not "
            "DNSSEC-signed, so validating senders discard it and DANE provides no "
            "protection.",
            f"Sign {apex_label} and publish its DS record at the parent, then verify "
            f"with: dig +dnssec TLSA _25._tcp.{host} — the response should carry the "
            "'ad' flag.",
        ] + suggestions
        info['reason'] = "TLSA matches but the zone is unsigned"

    info.update(status=status, suggestions=suggestions)
    return info


# ---------------------------------------------------------------------------
# Aggregation across MX hosts
# ---------------------------------------------------------------------------

def _group_host_infos(host_infos):
    """
    Collapse MX hosts whose findings are identical into one reporting group.

    Google Workspace publishes five MX hosts in one zone with one posture;
    printing five identical blocks buries the finding. Hosts are grouped only
    when nothing that matters differs, so no detail is lost — hosts that do have
    TLSA records are never grouped, since their certificates differ.
    """
    groups = []
    for info in host_infos:
        key = (
            info['has_tlsa'],
            info['status'],
            info['reason'],
            info['provider_name'],
            info['apex'],
            info['apex_signed'],
            info['scope_line'],
            tuple(info['notes']),
        )
        if not info['has_tlsa'] and groups and groups[-1]['key'] == key:
            groups[-1]['hosts'].append(info['host'])
        else:
            groups.append({'key': key, 'hosts': [info['host']], 'info': info})
    return groups


def _render_group(group, first_index, total):
    """Render one reporting group as a header line plus indented detail lines."""
    info  = group['info']
    hosts = group['hosts']

    if len(hosts) == 1:
        position = f"MX {first_index}/{total}"
        subject  = hosts[0]
    else:
        position = f"MX {first_index}-{first_index + len(hosts) - 1}/{total}"
        subject  = ", ".join(hosts)

    header = f"{position}: {subject}"
    if info['provider_name']:
        header += f" [{info['provider_name']}]"
    header += f" — {_STATUS_LABEL[info['status']]}: {info['reason']}"

    if len(hosts) == 1:
        tlsa_line  = info['tlsa_line'].replace('<host>', hosts[0])
        scope_line = info['scope_line']
    else:
        # Name a real host rather than a placeholder, then say the finding holds
        # for the rest — the reader can verify the claim with dig as written.
        tlsa_line = (
            info['tlsa_line'].replace('<host>', hosts[0])
            + f" (same for the other {len(hosts) - 1} host"
            + ("s)" if len(hosts) > 2 else ")")
        )
        scope_line = (info['scope_line'] or '').replace(
            'MX host is outside', 'MX hosts are outside') or None

    lines = [tlsa_line]
    if scope_line:
        lines.append(scope_line)
    lines.append(info['zone_line'])
    lines.extend(info['notes'])
    lines.extend(info['detail_lines'])
    return header, lines


def _aggregate_dane(domain, host_infos, skipped_hosts):
    """
    Reduce per-host results to the (records, status, summary, suggestions)
    contract used by every other check.

    Overall status is the worst per-host status: a sender is free to choose any
    MX, so the weakest host defines what the domain actually guarantees.
    """
    records     = []
    suggestions = []
    total       = len(host_infos)
    position    = 1

    for group in _group_host_infos(host_infos):
        header, lines = _render_group(group, position, total)
        records.append(header)
        records.extend(f"  {line}" for line in lines)
        suggestions.extend(group['info']['suggestions'])
        position += len(group['hosts'])

    if skipped_hosts:
        records.append(
            f"{len(skipped_hosts)} further MX host(s) not checked "
            f"(--dane-mx-limit): {', '.join(skipped_hosts)}"
        )

    status = max(
        (info['status'] for info in host_infos),
        key=lambda s: _STATUS_SEVERITY[s],
    )

    with_tlsa = sum(1 for info in host_infos if info['has_tlsa'])
    passing   = sum(1 for info in host_infos if info['status'] == 'ok')

    if passing == total:
        summary = (
            f"DANE is correctly configured on all {total} MX hosts for {domain}. "
            "Certificates are pinned in DNS and match what the servers serve."
            if total > 1 else
            "DANE is correctly configured. The mail server certificate is pinned in "
            "DNS and validates against the live certificate."
        )
        return records, status, summary, _dedupe(suggestions)

    # Distinct per-host reasons, worst first, so the summary leads with the
    # finding most likely to be actionable.
    reasons = _dedupe([
        info['reason'] for info in sorted(
            host_infos, key=lambda i: -_STATUS_SEVERITY[i['status']])
    ])

    if total == 1:
        summary = f"{reasons[0][0].upper()}{reasons[0][1:]}."
    elif with_tlsa == 0:
        summary = (
            f"None of the {total} MX hosts for {domain} publish TLSA records: "
            + "; ".join(reasons[:2]) + "."
        )
    elif with_tlsa < total:
        summary = (
            f"DANE coverage is incomplete: {with_tlsa} of {total} MX hosts for {domain} "
            "publish TLSA records. A sender may select any MX, so mail delivered to an "
            "unpinned host falls back to opportunistic TLS and the protection is only "
            "as good as the weakest host. Per host: " + "; ".join(reasons[:3]) + "."
        )
        suggestions.append(
            "Publish a TLSA record for every MX host, or remove the hosts that cannot "
            "have one. Partial coverage gives an attacker a downgrade path via the "
            "unprotected host."
        )
    else:
        summary = (
            f"All {total} MX hosts for {domain} publish TLSA records, but not all "
            "validate: " + "; ".join(reasons[:3]) + "."
        )

    return records, status, summary, _dedupe(suggestions)


# ---------------------------------------------------------------------------
# Entry point for the DANE check
# ---------------------------------------------------------------------------

def check_dane(domain, mx_hostname=None, third_party_status='warn',
               assume_self_hosted=False, mx_limit=5):
    """
    Check DANE configuration for every MX host of a domain.

    For each host:
      1. Locate the zone that would contain its TLSA record and test whether
         that zone is DNSSEC-signed.
      2. Look for TLSA records at _25._tcp.<host>.
      3. If present, retrieve the certificate served on port 25 and test every
         TLSA record against it; one match authenticates the host (RFC 7672).
      4. If absent, produce remediation appropriate to who operates the zone —
         TLSA publication steps for a self-hosted MX, provider-specific steps
         for a hosted one, since the operator cannot publish in a zone they do
         not control.

    Args:
        mx_hostname:        check this host only, instead of the domain's MX set.
        third_party_status: status used when a hosted provider offers no DANE
                            and no action is available to the domain owner.
        assume_self_hosted: treat MX hosts outside the domain as operator-run.
        mx_limit:           maximum MX hosts to check; 0 means all.
    """
    if mx_hostname:
        hosts = [mx_hostname.rstrip('.').lower()]
    else:
        raw_mx   = get_dns_records(domain, 'MX')
        mx_pairs = _sorted_mx_hosts(domain)
        if not mx_pairs:
            if raw_mx:
                # A null MX (RFC 7505) is a deliberate statement that the domain
                # accepts no mail, so there is nothing for DANE to protect.
                return (
                    [f"Null MX published: {raw_mx[0]}"],
                    "ok",
                    "The domain publishes a null MX (RFC 7505) and accepts no inbound "
                    "mail, so DANE does not apply.",
                    [],
                )
            return (
                ["No MX records found; DANE check skipped"],
                "missing",
                "Cannot check DANE without MX records.",
                [],
            )
        hosts = _dedupe([host for _, host in mx_pairs])

    skipped = []
    if mx_limit and len(hosts) > mx_limit:
        skipped = hosts[mx_limit:]
        hosts   = hosts[:mx_limit]

    host_infos = [
        _check_mx_host(domain, host, third_party_status, assume_self_hosted)
        for host in hosts
    ]
    return _aggregate_dane(domain, host_infos, skipped)


def format_provider_table():
    """Render the known-provider table for --list-providers."""
    posture = {
        'customer':  'yes, customer enables it',
        'migration': 'yes, on a different endpoint',
        'provider':  'yes, published by the provider',
        'no':        'no',
        'unknown':   'not established — determined at runtime',
    }
    width = max(len(p['name']) for p in _MAIL_PROVIDERS)
    lines = [
        "Mail providers recognised by the DANE check.",
        "",
        "Inbound DANE posture is only asserted where it has been verified. Entries",
        "marked 'not established' are listed so the report can name the provider;",
        "for those, whether DANE is possible is determined at runtime by testing",
        "whether the zone holding the MX hostname is DNSSEC-signed.",
        "",
        f"{'PROVIDER'.ljust(width)}  INBOUND DANE",
        f"{'-' * width}  {'-' * 32}",
    ]
    for provider in _MAIL_PROVIDERS:
        lines.append(f"{provider['name'].ljust(width)}  {posture[provider['inbound_dane']]}")
        lines.append(f"{' ' * width}  MX: {', '.join(provider['suffixes'])}")
    return "\n".join(lines)


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
    parser.add_argument(
        "--dane-strict", action="store_true",
        help=(
            "Report a missing TLSA record as FAIL even when the MX is operated by a "
            "third party that does not offer inbound DANE. The default is WARNING, "
            "since in that case there is no action available to the domain owner."
        ),
    )
    parser.add_argument(
        "--dane-self-hosted", action="store_true",
        help=(
            "Treat the MX hostname as a zone you operate even though it sits outside "
            "the checked domain (e.g. example.com with MX mail.example.net). Forces "
            "TLSA publication guidance instead of hosted-provider guidance."
        ),
    )
    parser.add_argument(
        "--dane-mx-limit", type=int, default=5, metavar="N",
        help=(
            "Maximum number of MX hosts to check for DANE, in preference order. "
            "Each host with a TLSA record costs one SMTP connection. "
            "Use 0 to check every host. Default: 5"
        ),
    )
    parser.add_argument(
        "--list-providers", action="store_true",
        help=(
            "Print the mail providers recognised by the DANE check, with their known "
            "inbound DANE posture, and exit."
        ),
    )

    args       = parser.parse_args()

    if args.list_providers:
        print(format_provider_table())
        sys.exit(0)

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
        ("DANE Record",    "dane",    lambda d: check_dane(
            d,
            third_party_status='missing' if args.dane_strict else 'warn',
            assume_self_hosted=args.dane_self_hosted,
            mx_limit=max(0, args.dane_mx_limit),
        )),
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
