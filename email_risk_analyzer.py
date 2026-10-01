#!/usr/bin/env python3
"""
Email Risk Analyzer
Defensive training project for detecting common phishing/spoofing indicators.

Safe scope:
- Parses supplied raw email files only.
- Uses synthetic/reserved example domains.
- Does not send email, contact external services, or follow links.
"""

import argparse
import html
import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse

URGENT_KEYWORDS = [
    "urgent", "immediately", "action required", "verify now",
    "account suspended", "final warning", "within 24 hours",
    "confirm your identity", "click now", "payment required",
    "security alert", "password expires"
]

SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".work", ".support"}

AUTH_FAIL_PATTERNS = {
    "spf": r"(?:spf|spf-authentication-results)[=:]\s*(fail|softfail|neutral|none|temperror|permerror)",
    "dkim": r"(?:dkim|dkim-signature)[=:]\s*(fail|none|temperror|permerror)"
}

def parse_email(path):
    raw = Path(path).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return msg, raw

def header_values(msg, name):
    return [str(v) for v in msg.get_all(name, [])]

def get_body(msg):
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    content = part.get_content()
                except Exception:
                    content = ""
                if ctype == "text/html":
                    content = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", content)
                    content = re.sub(r"(?s)<[^>]+>", " ", content)
                    content = html.unescape(content)
                parts.append(str(content))
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if msg.get_content_type() == "text/html":
            content = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", content)
            content = re.sub(r"(?s)<[^>]+>", " ", content)
            content = html.unescape(content)
        parts.append(str(content))
    return "\n".join(parts)

def extract_urls(text):
    # Intentionally only extracts text; never requests/follows a URL.
    return re.findall(r"https?://[^\s<>'\")]+", text, flags=re.I)

def domain_from_address(value):
    m = re.search(r"@([A-Za-z0-9.-]+)", value or "")
    return m.group(1).lower().rstrip(".") if m else ""

def host_from_url(url):
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""

def is_ip_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def analyze(msg, raw):
    from_addr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    subject = str(msg.get("Subject", ""))
    received = header_values(msg, "Received")
    auth_results = " ".join(header_values(msg, "Authentication-Results"))
    spf = " ".join(header_values(msg, "Received-SPF"))
    dkim = " ".join(header_values(msg, "DKIM-Signature"))
    body = get_body(msg)
    combined = f"{subject}\n{body}"

    findings = []
    score = 0

    def add(points, category, evidence, recommendation):
        nonlocal score
        score += points
        findings.append({
            "points": points,
            "category": category,
            "evidence": evidence,
            "recommendation": recommendation
        })

    from_domain = domain_from_address(from_addr)
    reply_domain = domain_from_address(reply_to)
    return_domain = domain_from_address(return_path)

    # Authentication indicators
    auth_lower = (auth_results + " " + spf + " " + dkim).lower()
    if re.search(r"\bspf[=:]\s*(fail|softfail|permerror)\b|\bspf\s+(fail|softfail|permerror)\b", auth_lower):
        add(25, "SPF failure", "SPF result indicates fail/softfail/permerror.",
            "Treat sender authenticity as untrusted and verify through an independent channel.")
    elif "spf=pass" in auth_lower or "spf: pass" in auth_lower:
        findings.append({"points": 0, "category": "SPF pass", "evidence": "SPF result indicates pass.",
                         "recommendation": "SPF pass is helpful but does not prove the message is safe."})

    if re.search(r"\bdkim[=:]\s*(fail|permerror|temperror)\b|\bdkim\s+(fail|permerror|temperror)\b", auth_lower):
        add(25, "DKIM failure", "DKIM result indicates fail/error.",
            "Do not rely on the message identity; verify the sender independently.")
    elif "dkim=pass" in auth_lower:
        findings.append({"points": 0, "category": "DKIM pass", "evidence": "DKIM result indicates pass.",
                         "recommendation": "DKIM pass supports message integrity but is not a guarantee of safety."})

    # Header consistency
    if from_domain and reply_domain and from_domain != reply_domain:
        add(15, "Reply-To mismatch", f"From domain '{from_domain}' differs from Reply-To '{reply_domain}'.",
            "Confirm the expected reply domain before responding.")
    if from_domain and return_domain and from_domain != return_domain:
        add(10, "Return-Path mismatch", f"From domain '{from_domain}' differs from Return-Path '{return_domain}'.",
            "Check whether the difference is expected for the sender's mail infrastructure.")

    # Received chain
    if len(received) == 0:
        add(5, "Missing Received chain", "No Received headers were found.",
            "A real mail path normally contains Received headers; treat missing metadata cautiously.")
    elif len(received) > 6:
        add(3, "Long Received chain", f"{len(received)} Received headers detected.",
            "Review the mail path for unexpected relays or forwarding.")

    # Urgency
    lower = combined.lower()
    matched_urgent = sorted(set(k for k in URGENT_KEYWORDS if k in lower))
    if matched_urgent:
        pts = min(20, 5 + 3 * len(matched_urgent))
        add(pts, "Urgent lure language", ", ".join(matched_urgent),
            "Avoid acting under pressure; verify the request using a known contact method.")

    # URLs
    urls = extract_urls(body)
    if urls:
        suspicious = []
        for u in urls:
            host = host_from_url(u)
            if not host:
                continue
            if is_ip_host(host) or host.startswith("xn--") or any(host.endswith(t) for t in SUSPICIOUS_TLDS):
                suspicious.append(u)
        if suspicious:
            add(min(20, 8 + 4 * len(suspicious)), "Suspicious URL host",
                "; ".join(suspicious[:5]),
                "Do not open the link; navigate to the organization's known website manually.")
        else:
            findings.append({"points": 0, "category": "URLs detected",
                             "evidence": f"{len(urls)} URL(s) found; no basic host red flags matched.",
                             "recommendation": "Still verify the destination before clicking."})

    # Lookalike / spoof wording
    spoof_terms = ["verify your microsoft", "verify your google", "paypal security",
                   "bank security", "office 365", "microsoft 365", "account security"]
    matched_spoof = sorted(set(x for x in spoof_terms if x in lower))
    if matched_spoof and from_domain and not any(x in from_domain for x in ["example.com", "example.org", "example.net"]):
        add(10, "Brand impersonation wording", ", ".join(matched_spoof),
            "Compare the sender domain with the organization's legitimate domain.")

    # Attachment lure
    attachment_names = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachment_names.append(filename)
    risky_ext = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso", ".img", ".zip")
    risky_files = [n for n in attachment_names if n.lower().endswith(risky_ext)]
    if risky_files:
        add(20, "Potentially risky attachment", ", ".join(risky_files),
            "Do not execute or open suspicious attachments; submit them to approved security tooling.")

    score = min(score, 100)
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    elif score >= 20:
        level = "LOW"
    else:
        level = "MINIMAL"

    return {
        "risk_score": score,
        "risk_level": level,
        "headers": {
            "From": from_addr,
            "Reply-To": reply_to,
            "Return-Path": return_path,
            "Subject": subject,
            "Received_Count": len(received),
            "Authentication-Results": header_values(msg, "Authentication-Results"),
            "Received-SPF": header_values(msg, "Received-SPF"),
            "DKIM-Signature": dkim,
        },
        "urls_found": urls,
        "attachments": attachment_names,
        "findings": findings,
        "summary": (
            f"{level} risk ({score}/100). The score reflects only indicators "
            f"detected by this training analyzer; it is not proof that a message is malicious."
        )
    }

def analyze_file(path):
    msg, raw = parse_email(path)
    return analyze(msg, raw)

def main():
    parser = argparse.ArgumentParser(description="Analyze a raw email for phishing and spoofing indicators.")
    parser.add_argument("email", nargs="?", help="Path to a .eml file")
    parser.add_argument("--json", dest="json_out", help="Write analysis JSON to this path")
    parser.add_argument("--all", action="store_true", help="Analyze all .eml files in sample_emails/")
    args = parser.parse_args()

    files = []
    if args.all:
        files = sorted(Path("sample_emails").glob("*.eml"))
    elif args.email:
        files = [Path(args.email)]
    else:
        parser.error("Provide an email file or use --all.")

    results = {}
    for f in files:
        result = analyze_file(f)
        results[str(f)] = result
        print("=" * 72)
        print(f"FILE: {f}")
        print(f"RISK: {result['risk_level']} ({result['risk_score']}/100)")
        print(result["summary"])
        for finding in result["findings"]:
            if finding["points"]:
                print(f"- +{finding['points']} {finding['category']}: {finding['evidence']}")
        print()

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"JSON report written to {args.json_out}")

if __name__ == "__main__":
    main()
