
A static analysis and threat-intelligence verification tool that scans raw email files for phishing and spoofing indicators, then cross-checks its own findings against real-world threat intelligence APIs to give a final verdict.

 This tool is built around a two-stage model: an independent heuristic engine that judges the email on its own structural and linguistic merits, and a verification layer that confirms (or contradicts) those findings against external reputation services — VirusTotal and Google Safe Browsing. The disagreement between the two is itself reported, because in real-world triage, knowing *where* automated systems disagree is often more useful than a single confidence number.

```
$ email-forensics --file suspicious_email.txt

──────────────────── Email Forensics Report ────────────────────

                    Header Analysis
┌───────────────┬────────────────────────────────────┐
│ From          │ PayPal Security <security@paypa1…  │
│ Reply-To      │ response-team@secure-paypaI.com    │
│ SPF           │ not present                        │
│ DMARC         │ not present                        │
└───────────────┴────────────────────────────────────┘

                    Heuristic Flags
┌──────────┬────────────────────────┬───────────────┐
│ Severity │ Rule                   │ Description   │
│       65 │ anchor_text_mismatch   │ ...           │
│       55 │ ip_literal_url         │ ...           │
└──────────┴────────────────────────┴───────────────┘

╭──────────────── Final Verdict ─────────────────╮
│ VERDICT: Likely Phishing                       │
│ Final Score: 100/100                           │
╰────────────────────────────────────────────────╯
```

## How it works

The pipeline runs in four stages:

1. **Parsing** (`parser.py`) — reads the raw email and extracts headers (`From`, `Reply-To`, `Return-Path`, `Received chain`, `Message-ID`, `Authentication-Results`), plain-text and HTML bodies, every URL (including ones hidden behind HTML anchor text), and attachment metadata.

2. **Heuristic analysis** (`heuristics.py`) — runs a set of independent rules against the parsed data and assigns each a severity-weighted flag if triggered:
   - Header mismatches: `From` vs `Reply-To` vs `Return-Path` vs `Message-ID` domains
   - SPF / DKIM / DMARC authentication failures
   - Suspiciously short or missing Received chains
   - Urgency/pressure language common in social engineering
   - URL red flags: IP-literal links, known shorteners, typosquatted brand domains (via similarity scoring), and **anchor-text spoofing** (visible link text that doesn't match the real destination)
   - Attachment red flags: double extensions (`invoice.pdf.exe`), executable/script file types, anomalously small Office documents
   - Zero-width Unicode character obfuscation (used to evade keyword filters)

3. **External verification** (`verification.py`) — takes every URL found in the email and checks it against VirusTotal and Google Safe Browsing's live threat databases. This is the integrity check: it confirms whether the heuristic engine's suspicions match what real-world threat intelligence actually knows about these URLs.

4. **Verdict synthesis** (`verdict.py`) — combines the internal heuristic score with external confirmation into one of four labels: `Clean`, `Suspicious`, `Likely Phishing`, `Confirmed Malicious`. If external services confirm malicious activity, that takes priority over the internal score. If the two sources disagree, the report says so explicitly rather than silently picking one.

## Installation

```bash
git clone https://github.com/ArihantGarg1386/Phishing-email-Analyzer
pip install -r requirements.txt
```

### API keys (optional but recommended)

External verification requires free API keys from VirusTotal and Google Safe Browsing.

```bash
cp .env.example .env
# then edit .env and add your keys
```

| Service | Free tier | Get a key |
|---|---|---|
| VirusTotal | ~4 requests/min | https://www.virustotal.com/gui/join-us |
| Google Safe Browsing | 10,000 requests/day | https://developers.google.com/safe-browsing/v4/get-started |

Without API keys, the tool still runs and produces a full report based on heuristics alone — external verification tables simply note that no API keys were configured. Just append the `--no-api ` flag at the end.

## Usage

```bash
# Full analysis with external verification
python -m email_forensics.cli --file path/to/email.txt

# Heuristics only, skip external API calls 
python -m email_forensics.cli --file path/to/email.txt --no-api

# Also save the full structured result as JSON
python -m email_forensics.cli --file path/to/email.txt --json result.json
```

There are three samples designed to land in three different verdict tiers (`Clean`, `Suspicious`, `Likely Phishing`), so you can see the scoring model differentiate between them immediately.

## Scoring methodology

Each heuristic rule contributes a severity weight (10–90) when triggered. The internal score is the sum of all triggered weights, capped at 100. The final score additionally factors in external confirmation: a confirmed-malicious URL from VirusTotal or Safe Browsing pulls the final score to at least 90, regardless of how the internal heuristics scored it, because live threat intelligence on a specific indicator is treated as a stronger signal than static pattern-matching alone.

| Score range | Verdict |
|---|---|
| 0–34 | Clean |
| 35–69 | Suspicious |
| 70–100 (no external confirmation) | Likely Phishing |
| Any score, with external confirmation | Confirmed Malicious |

## Project structure

```
email-forensics/
├── src/email_forensics/
│   ├── parser.py          # Email parsing — headers, body, URLs, attachments
│   ├── heuristics.py       # Rule-based detection engine
│   ├── verification.py     # VirusTotal / Safe Browsing API integration
│   ├── verdict.py          # Score combination and final classification
│   ├── report.py           # Rich terminal report rendering
│   └── cli.py               # Command-line entry point
├── tests/
│   ├── sample_emails/      # Clean, borderline, and phishing test cases
│   └── test_heuristics.py
├── requirements.txt
├── .env.example
└── setup.py
```

## Limitations

This is a static analysis tool — it does not execute attachments in a sandbox, follow redirect chains, or render JavaScript. Typosquat detection uses string-similarity scoring against a small fixed brand list rather than a comprehensive database. VirusTotal's free tier rate limit (~4 requests/min) means analysis of emails with many URLs will be slower; the `--no-api` flag is provided for quick iteration during development or demos.

## License

MIT — see [LICENSE](LICENSE).
