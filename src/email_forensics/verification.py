"""
This is the "compare against open-source/external threat intel" layer.
Our own heuristics.py makes an independent judgment; this module checks
the same indicators (mainly URLs) against real-world reputation services
so the final verdict isn't based on guesswork alone.

Two providers are used here:
  - VirusTotal (https://www.virustotal.com) — free tier, ~4 req/min
  - Google Safe Browsing (https://safebrowsing.google.com) — free tier

If no API keys are configured, the tool still runs on heuristics alone.
(see --no-api flag in cli.py).
"""

from __future__ import annotations

import os
import time
import base64
import requests
from dataclasses import dataclass, field

VT_BASE_URL = "https://www.virustotal.com/api/v3"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# VirusTotal free tier is rate-limited; we pace requests to stay under it.
VT_REQUEST_DELAY_SECONDS = 16  # ~4/min


@dataclass
class URLVerdict:
    url: str
    source: str  # "virustotal" or "safe_browsing"
    malicious: bool
    detail: str
    raw_stats: dict = field(default_factory=dict)


def _vt_api_key() -> str | None:
    return os.environ.get("VT_API_KEY")


def _gsb_api_key() -> str | None:
    return os.environ.get("GSB_API_KEY")


def check_url_virustotal(url: str) -> URLVerdict | None:
    """Submits a URL identifier to VirusTotal and returns the analysis stats.
    VT identifies URLs by the base64 of the URL without padding."""
    api_key = _vt_api_key()
    if not api_key:
        return None

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=10)
        if resp.status_code == 404:
            # Not previously scanned — submit it, then report "pending" rather than
            # blocking the whole run waiting for analysis to finish.
            requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url}, timeout=10)
            return URLVerdict(
                url=url, source="virustotal", malicious=False,
                detail="URL not previously seen by VirusTotal; submitted for analysis "
                       "(results not available within this run).",
            )
        resp.raise_for_status()
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return URLVerdict(
            url=url,
            source="virustotal",
            malicious=malicious_count > 0,
            detail=f"{malicious_count} of {sum(stats.values())} engines flagged this URL.",
            raw_stats=stats,
        )
    except requests.RequestException as exc:
        return URLVerdict(url=url, source="virustotal", malicious=False, detail=f"API error: {exc}")


def check_url_safe_browsing(url: str) -> URLVerdict | None:
    api_key = _gsb_api_key()
    if not api_key:
        return None

    body = {
        "client": {"clientId": "email-forensics-tool", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(f"{SAFE_BROWSING_URL}?key={api_key}", json=body, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            threat_types = ", ".join(sorted({m["threatType"] for m in matches}))
            return URLVerdict(
                url=url, source="safe_browsing", malicious=True,
                detail=f"Flagged for: {threat_types}",
            )
        return URLVerdict(url=url, source="safe_browsing", malicious=False, detail="No known threats found.")
    except requests.RequestException as exc:
        return URLVerdict(url=url, source="safe_browsing", malicious=False, detail=f"API error: {exc}")


def verify_urls(urls: list[str], use_virustotal: bool = True, use_safe_browsing: bool = True) -> list[URLVerdict]:
    """Runs external verification across all providers for a deduplicated URL list.
    Paces VirusTotal calls to respect the free-tier rate limit."""
    results: list[URLVerdict] = []
    unique_urls = list(dict.fromkeys(urls))  # dedupe, preserve order

    for i, url in enumerate(unique_urls):
        if use_safe_browsing and _gsb_api_key():
            verdict = check_url_safe_browsing(url)
            if verdict:
                results.append(verdict)

        if use_virustotal and _vt_api_key():
            verdict = check_url_virustotal(url)
            if verdict:
                results.append(verdict)
            if i < len(unique_urls) - 1:
                time.sleep(VT_REQUEST_DELAY_SECONDS)

    return results
