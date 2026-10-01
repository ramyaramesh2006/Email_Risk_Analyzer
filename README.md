# Email Risk Analyzer

A beginner-friendly defensive cybersecurity project that analyzes raw `.eml` files for common phishing and spoofing indicators.

## Objective

Identify:
- SPF/DKIM authentication failures
- `From`, `Reply-To`, and `Return-Path` mismatches
- suspicious or unusual URL hosts
- urgent/action-pressure language
- suspicious brand-impersonation wording
- potentially risky attachments
- unusual/missing `Received` header information

Then assign a 0-100 triage score and generate a security audit report.

## Project structure

```text
Email_Risk_Analyzer/
├── email_risk_analyzer.py
├── generate_report.py
├── requirements.txt
├── README.md
├── sample_emails/
│   ├── 01_safe_newsletter.eml
│   ├── 02_phishing_urgent.eml
│   └── 03_phishing_reply_mismatch.eml
└── reports/
    └── Phishing_Analysis_Report.pdf
```

## Run on Windows

Open PowerShell inside this folder:

```powershell
py -m pip install -r requirements.txt
py email_risk_analyzer.py --all
py generate_report.py
```

Or analyze one email:

```powershell
py email_risk_analyzer.py sample_emails\02_phishing_urgent.eml
```

## Output

The analyzer prints:
- risk score
- risk level
- detected phishing indicators
- evidence
- recommended defensive action

`generate_report.py` creates:
`reports/Phishing_Analysis_Report.pdf`

## Scoring used

- SPF failure: +25
- DKIM failure: +25
- Reply-To mismatch: +15
- Return-Path mismatch: +10
- urgent lure language: up to +20
- suspicious URL host: up to +20
- brand impersonation wording: +10
- risky attachment: +20
- missing/long Received chain: small triage adjustment

The final score is capped at 100.

## Viva explanation

**What is the project?**
It is a defensive email security analyzer. It reads a raw email, checks headers and body text, identifies phishing indicators, calculates a risk score, and produces an audit report.

**Why SPF?**
SPF checks whether the sending server is authorized by the domain's SPF policy. A failure is a warning sign, but it is not by itself proof of phishing.

**Why DKIM?**
DKIM uses a cryptographic signature to help verify message integrity and domain association. A failure is a warning sign.

**Why Received headers?**
They provide the recorded mail path through receiving servers. They can help investigators understand how a message traveled.

**Why check Reply-To?**
An attacker may display one sender identity while directing replies to a different domain.

**Why check urgent words?**
Phishing emails often create pressure so the victim acts before verifying the request.

**Does the tool open links?**
No. URLs are extracted as text only. The project intentionally does not make network requests.

## Safety

All sample data uses reserved/example domains and synthetic metadata. No real accounts or live links are used. The analyzer is designed for defensive education and local file analysis.
