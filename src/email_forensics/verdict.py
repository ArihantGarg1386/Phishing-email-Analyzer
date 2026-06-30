"""
Combines the internal heuristic score with external verification results
into one final classification. This is the "final answer" the tool gives.

Weighting logic (documented here so it's easy to defend in a writeup/demo):
  - Internal heuristic score: 0-100, our own static analysis
  - External confirmation: any externally-confirmed malicious URL pushes
    the verdict to the top tier almost regardless of internal score,
    because real-world reputation data is the strongest signal available.
  - If internal and external disagree, we say so explicitly — that
    disagreement is itself useful information for the analyst.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .heuristics import Flag
from .verification import URLVerdict

VERDICT_LABELS = ["Clean", "Suspicious", "Likely Phishing", "Confirmed Malicious"]


@dataclass
class FinalVerdict:
    label: str
    final_score: int
    internal_score: int
    external_confirmed_malicious: bool
    agreement_note: str
    flags: list = field(default_factory=list)
    url_verdicts: list = field(default_factory=list)


def _label_from_score(score: int, external_confirmed: bool) -> str:
    if external_confirmed:
        return "Confirmed Malicious"
    if score >= 70:
        return "Likely Phishing"
    if score >= 35:
        return "Suspicious"
    return "Clean"


def build_verdict(
    flags: list[Flag],
    internal_score: int,
    url_verdicts: list[URLVerdict],
) -> FinalVerdict:
    external_confirmed = any(v.malicious for v in url_verdicts)
    external_checked = len(url_verdicts) > 0

    if external_confirmed:
        final_score = max(internal_score, 90)
    else:
        final_score = internal_score

    label = _label_from_score(final_score, external_confirmed)

    if not external_checked:
        agreement_note = ("No external verification performed (no API keys configured, or no URLs "
                           "found to check) — verdict is based on heuristics only.")
    elif external_confirmed and internal_score < 35:
        agreement_note = ("External threat intelligence flagged this email as malicious even though "
                           "internal heuristics found relatively few red flags — external data overrides.")
    elif not external_confirmed and internal_score >= 70:
        agreement_note = ("Internal heuristics found strong red flags, but no external service has "
                           "this URL on record yet (it may be a newly-registered phishing domain).")
    else:
        agreement_note = "Internal heuristics and external threat intelligence are in agreement."

    return FinalVerdict(
        label=label,
        final_score=final_score,
        internal_score=internal_score,
        external_confirmed_malicious=external_confirmed,
        agreement_note=agreement_note,
        flags=flags,
        url_verdicts=url_verdicts,
    )
