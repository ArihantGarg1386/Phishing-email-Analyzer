import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from email_forensics.parser import parse_email_file
from email_forensics.heuristics import run_all_heuristics, compute_internal_score
from email_forensics.verdict import build_verdict

SAMPLES_DIR = Path(__file__).parent / "sample_emails"


def _analyze(filename: str):
    email_obj = parse_email_file(str(SAMPLES_DIR / filename))
    flags = run_all_heuristics(email_obj)
    score = compute_internal_score(flags)
    verdict = build_verdict(flags, score, url_verdicts=[])
    return email_obj, flags, verdict


def test_clean_sample_scores_low():
    _, flags, verdict = _analyze("clean_sample.txt")
    assert verdict.internal_score < 35
    assert verdict.label == "Clean"


def test_phishing_sample_scores_high():
    _, flags, verdict = _analyze("phishing_sample.txt")
    assert verdict.internal_score >= 70
    assert verdict.label in ("Likely Phishing", "Confirmed Malicious")
    rule_names = {f.rule for f in flags}
    assert "reply_to_mismatch" in rule_names
    assert "urgency_language" in rule_names
    assert "ip_literal_url" in rule_names


def test_phishing_sample_detects_anchor_mismatch():
    _, flags, _ = _analyze("phishing_sample.txt")
    rule_names = {f.rule for f in flags}
    assert "anchor_text_mismatch" in rule_names


def test_borderline_sample_is_in_middle_range():
    _, flags, verdict = _analyze("borderline_sample.txt")
    assert 35 <= verdict.internal_score < 70
    assert verdict.label == "Suspicious"
    rule_names = {f.rule for f in flags}
    assert "dkim_fail" in rule_names


if __name__ == "__main__":
    test_clean_sample_scores_low()
    test_phishing_sample_scores_high()
    test_phishing_sample_detects_anchor_mismatch()
    test_borderline_sample_is_in_middle_range()
    print("All tests passed.")
