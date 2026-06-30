"""
Parses a raw .eml / .txt email file into a structured representation
that downstream modules (heuristics, verification, verdict) can consume.

Design note:It extracts facts (headers, urls, attachments) and makes
no judgments about whetheranything is suspicious. That logic lives in heuristics.py.
"""

from __future__ import annotations

import re
import email
from email import policy
from email.message import Message
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

URL_REGEX = re.compile(
    r"(?:(?:https?|hxxp[s]?)://|www\.)[^\s\"'<>\)\]]+", re.IGNORECASE
)
ANCHOR_REGEX = re.compile(
    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
)
ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]


@dataclass
class ParsedURL:
    raw: str
    domain: str
    is_ip_literal: bool = False
    anchor_text: str | None = None  # the visible text, if found inside HTML
    mismatched_anchor: bool = False


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int


@dataclass
class ParsedEmail:
    source_path: str
    raw_headers: dict
    from_addr: str | None
    reply_to: str | None
    return_path: str | None
    to_addr: str | None
    subject: str | None
    message_id: str | None
    received_chain: list
    auth_results_raw: str | None
    spf_result: str | None
    dkim_result: str | None
    dmarc_result: str | None
    body_text: str
    body_html: str
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    has_zero_width_chars: bool = False


def _extract_domain(addr: str | None) -> str | None:
    if not addr:
        return None
    match = re.search(r"@([\w.\-]+)", addr)
    return match.group(1).lower() if match else None


def _parse_auth_results(raw: str | None) -> tuple:
    """Pulls spf=/dkim=/dmarc= verdicts out of an Authentication-Results header."""
    if not raw:
        return None, None, None

    def grab(field_name: str) -> str | None:
        m = re.search(rf"{field_name}=(\w+)", raw, re.IGNORECASE)
        return m.group(1).lower() if m else None

    return grab("spf"), grab("dkim"), grab("dmarc")


def _find_urls_plain(text: str) -> list[ParsedURL]:
    found = []
    for raw in URL_REGEX.findall(text or ""):
        cleaned = raw.rstrip(".,;:!?")
        domain = urlparse(cleaned if "://" in cleaned else f"//{cleaned}").hostname or cleaned
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain or ""))
        found.append(ParsedURL(raw=cleaned, domain=domain.lower() if domain else "", is_ip_literal=is_ip))
    return found


def _find_urls_html(html: str) -> list[ParsedURL]:
    """Extracts <a href=...>text</a> pairs so we can detect link-text spoofing,
    e.g. <a href="http://evil.tld">paypal.com</a>."""
    found = []
    for href, anchor_text in ANCHOR_REGEX.findall(html or ""):
        anchor_text_clean = re.sub("<[^<]+?>", "", anchor_text).strip()
        domain = urlparse(href).hostname or href
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain or ""))

        mismatched = False
        # If the visible text itself looks like a URL/domain, but it doesn't
        # match the real destination domain, that's a classic phishing trick.
        anchor_domain_match = re.search(r"([\w\-]+\.[\w\-]+(?:\.[\w\-]+)?)", anchor_text_clean)
        if anchor_domain_match and domain:
            anchor_domain = anchor_domain_match.group(1).lower()
            if anchor_domain not in domain.lower() and domain.lower() not in anchor_domain:
                mismatched = True

        found.append(
            ParsedURL(
                raw=href,
                domain=domain.lower() if domain else "",
                is_ip_literal=is_ip,
                anchor_text=anchor_text_clean or None,
                mismatched_anchor=mismatched,
            )
        )
    return found


def parse_email_file(filepath: str) -> ParsedEmail:
    """Main entry point: reads a .eml/.txt file from disk and returns a ParsedEmail."""
    path = Path(filepath)
    raw_bytes = path.read_bytes()
    msg: Message = email.message_from_bytes(raw_bytes, policy=policy.default)

    raw_headers = {k: v for k, v in msg.items()}

    received_chain = msg.get_all("Received", [])
    auth_results_raw = msg.get("Authentication-Results")
    spf, dkim, dmarc = _parse_auth_results(auth_results_raw)

    body_text = ""
    body_html = ""
    attachments: list[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition") or "")
            content_type = part.get_content_type()

            if "attachment" in content_disposition or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    Attachment(
                        filename=part.get_filename() or "unnamed",
                        content_type=content_type,
                        size_bytes=len(payload),
                    )
                )
            elif content_type == "text/plain" and not body_text:
                body_text = part.get_content()
            elif content_type == "text/html" and not body_html:
                body_html = part.get_content()
    else:
        if msg.get_content_type() == "text/html":
            body_html = msg.get_content()
        else:
            body_text = msg.get_content()

    urls = _find_urls_plain(body_text) + _find_urls_html(body_html)

    full_text_blob = (body_text or "") + (body_html or "")
    has_zwc = any(ch in full_text_blob for ch in ZERO_WIDTH_CHARS)

    return ParsedEmail(
        source_path=str(path),
        raw_headers=raw_headers,
        from_addr=msg.get("From"),
        reply_to=msg.get("Reply-To"),
        return_path=msg.get("Return-Path"),
        to_addr=msg.get("To"),
        subject=msg.get("Subject"),
        message_id=msg.get("Message-ID"),
        received_chain=received_chain,
        auth_results_raw=auth_results_raw,
        spf_result=spf,
        dkim_result=dkim,
        dmarc_result=dmarc,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
        has_zero_width_chars=has_zwc,
    )
