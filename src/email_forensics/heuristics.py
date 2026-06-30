"""
heuristics.py
--------------
Rule-based detection engine. Each rule inspects the ParsedEmail and,
if triggered, emits a Flag with a severity weight. The sum of weights
becomes the "internal score" — our own independent judgment before
we ever talk to an external API.

Severity scale (rough guide):
  10-20  minor oddity, common in legitimate mail too
  30-50  meaningful red flag
  60-90  strong indicator of malicious intent
  100    near-certain compromise indicator
"""

from __future__ import annotations

import re
import difflib
from dataclasses import dataclass

from .parser import ParsedEmail

# Brands most commonly impersonated in phishing campaigns.
# Used for typosquat / lookalike-domain detection.
COMMON_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "netflix.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "dropbox.com", "linkedin.com", "instagram.com",
]

KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorturl.at", "cutt.ly",
}

URGENCY_PHRASES = [
    "verify your account", "account suspended", "act now", "urgent action required",
    "click here immediately", "confirm your identity", "your account will be closed",
    "unusual activity", "limited time", "final notice", "failure to comply",
    "within 24 hours", "your password will expire", "click below to avoid",
    "immediate attention required", "security alert",
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".com", ".pif",
}

DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}


@dataclass
class Flag:
    rule: str
    severity: int
    description: str


def _domain_root(addr_header: str | None) -> str | None:
    if not addr_header:
        return None
    m = re.search(r"@([\w.\-]+)", addr_header)
    return m.group(1).lower() if m else None


def check_header_mismatches(email_obj: ParsedEmail) -> list[Flag]:
    flags = []
    from_domain = _domain_root(email_obj.from_addr)
    reply_domain = _domain_root(email_obj.reply_to)
    return_domain = _domain_root(email_obj.return_path)

    if reply_domain and from_domain and reply_domain != from_domain:
        flags.append(Flag(
            rule="reply_to_mismatch",
            severity=45,
            description=f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}' "
                        f"— replies are silently redirected elsewhere.",
        ))

    if return_domain and from_domain and return_domain != from_domain:
        flags.append(Flag(
            rule="return_path_mismatch",
            severity=35,
            description=f"Return-Path domain '{return_domain}' differs from From domain '{from_domain}' "
                        f"— bounce handling does not match the claimed sender.",
        ))

    if email_obj.message_id:
        msgid_match = re.search(r"@([\w.\-]+)>?$", email_obj.message_id.strip())
        msgid_domain = msgid_match.group(1).lower() if msgid_match else None
        if msgid_domain and from_domain and msgid_domain != from_domain:
            flags.append(Flag(
                rule="message_id_mismatch",
                severity=20,
                description=f"Message-ID domain '{msgid_domain}' does not match From domain "
                             f"'{from_domain}'.",
            ))

    return flags


def check_auth_results(email_obj: ParsedEmail) -> list[Flag]:
    flags = []
    if email_obj.spf_result and email_obj.spf_result not in ("pass",):
        flags.append(Flag(
            rule="spf_fail",
            severity=50,
            description=f"SPF check result is '{email_obj.spf_result}' (expected 'pass') — "
                         f"sending server is not authorized for this domain.",
        ))
    if email_obj.dkim_result and email_obj.dkim_result not in ("pass",):
        flags.append(Flag(
            rule="dkim_fail",
            severity=40,
            description=f"DKIM check result is '{email_obj.dkim_result}' (expected 'pass') — "
                         f"message signature did not verify.",
        ))
    if email_obj.dmarc_result and email_obj.dmarc_result not in ("pass",):
        flags.append(Flag(
            rule="dmarc_fail",
            severity=55,
            description=f"DMARC check result is '{email_obj.dmarc_result}' (expected 'pass') — "
                         f"message fails the domain's own anti-spoofing policy.",
        ))
    if not email_obj.auth_results_raw:
        flags.append(Flag(
            rule="no_auth_results_header",
            severity=15,
            description="No Authentication-Results header present — SPF/DKIM/DMARC could not be verified "
                        "from headers alone.",
        ))
    return flags


def check_received_chain(email_obj: ParsedEmail) -> list[Flag]:
    flags = []
    hops = email_obj.received_chain
    if len(hops) == 0:
        flags.append(Flag(
            rule="missing_received_headers",
            severity=30,
            description="No Received headers found — the routing path of this message cannot be traced, "
                        "which is unusual for genuinely delivered mail.",
        ))
    elif len(hops) == 1:
        flags.append(Flag(
            rule="minimal_received_chain",
            severity=15,
            description="Only one Received header found — very short delivery chains can indicate "
                        "direct injection rather than normal mail routing.",
        ))
    return flags


def check_urgency_language(email_obj: ParsedEmail) -> list[Flag]:
    flags = []
    haystack = f"{email_obj.subject or ''} {email_obj.body_text or ''} {email_obj.body_html or ''}".lower()
    hits = [p for p in URGENCY_PHRASES if p in haystack]
    if hits:
        flags.append(Flag(
            rule="urgency_language",
            severity=min(10 * len(hits), 50),
            description=f"Detected {len(hits)} urgency/pressure phrase(s) commonly used in phishing: "
                        + ", ".join(f"'{h}'" for h in hits[:5]),
        ))
    return flags


def _is_typosquat(domain: str) -> str | None:
    """Returns the brand it resembles if domain looks like a typosquat, else None."""
    if not domain:
        return None
    for brand in COMMON_BRANDS:
        if domain == brand:
            return None  # exact match, legitimate
        ratio = difflib.SequenceMatcher(None, domain, brand).ratio()
        if ratio > 0.82:
            return brand
    return None


def check_urls(email_obj: ParsedEmail) -> list[Flag]:
    flags = []
    seen_domains = set()

    for url in email_obj.urls:
        if url.domain in seen_domains:
            continue
        seen_domains.add(url.domain)

        if url.is_ip_literal:
            flags.append(Flag(
                rule="ip_literal_url",
                severity=55,
                description=f"Link points directly to an IP address ({url.domain}) rather than a domain name "
                            f"— common technique to bypass domain reputation filters.",
            ))

        if url.domain in KNOWN_URL_SHORTENERS:
            flags.append(Flag(
                rule="url_shortener",
                severity=25,
                description=f"Link uses URL shortener '{url.domain}', which obscures the real destination.",
            ))

        brand_match = _is_typosquat(url.domain)
        if brand_match:
            flags.append(Flag(
                rule="typosquat_domain",
                severity=70,
                description=f"Domain '{url.domain}' closely resembles trusted brand '{brand_match}' "
                            f"— likely a lookalike/typosquat domain.",
            ))

        if url.mismatched_anchor:
            flags.append(Flag(
                rule="anchor_text_mismatch",
                severity=65,
                description=f"Visible link text reads '{url.anchor_text}' but actually points to "
                            f"'{url.domain}' — the displayed link is deceptive.",
            ))

    return flags


def check_attachments(email_obj: ParsedEmail) -> list[Flag]:
    flags = []
    for att in email_obj.attachments:
        name = att.filename.lower()
        parts = name.split(".")

        # Double-extension trick: invoice.pdf.exe
        if len(parts) > 2:
            real_ext = f".{parts[-1]}"
            fake_ext = f".{parts[-2]}"
            if real_ext in EXECUTABLE_EXTENSIONS and fake_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png"}:
                flags.append(Flag(
                    rule="double_extension_spoof",
                    severity=90,
                    description=f"Attachment '{att.filename}' uses a double extension to disguise an "
                                f"executable ('{fake_ext}{real_ext}') as a document.",
                ))

        for ext in EXECUTABLE_EXTENSIONS:
            if name.endswith(ext):
                flags.append(Flag(
                    rule="executable_attachment",
                    severity=80,
                    description=f"Attachment '{att.filename}' is an executable/script type ({ext}).",
                ))
                break

        if name.endswith((".doc", ".docx", ".xls", ".xlsm")) and att.size_bytes < 2048:
            flags.append(Flag(
                rule="suspicious_small_office_doc",
                severity=20,
                description=f"Office attachment '{att.filename}' is unusually small ({att.size_bytes} bytes) "
                            f"for its type — worth manual inspection.",
            ))

    return flags


def check_zero_width_obfuscation(email_obj: ParsedEmail) -> list[Flag]:
    flags = []
    if email_obj.has_zero_width_chars:
        flags.append(Flag(
            rule="zero_width_obfuscation",
            severity=60,
            description="Zero-width or invisible Unicode characters detected in the message body — "
                        "a technique used to evade keyword-based spam/phishing filters.",
        ))
    return flags


ALL_RULES = [
    check_header_mismatches,
    check_auth_results,
    check_received_chain,
    check_urgency_language,
    check_urls,
    check_attachments,
    check_zero_width_obfuscation,
]


def run_all_heuristics(email_obj: ParsedEmail) -> list[Flag]:
    """Runs every registered rule and returns the combined flat list of flags."""
    flags: list[Flag] = []
    for rule_fn in ALL_RULES:
        flags.extend(rule_fn(email_obj))
    return flags


def compute_internal_score(flags: list[Flag]) -> int:
    """Sums severities and caps at 100 so internal score is comparable to a percentage."""
    return min(sum(f.severity for f in flags), 100)
