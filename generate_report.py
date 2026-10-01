#!/usr/bin/env python3
"""Generate a PDF audit report from synthetic sample emails."""
from pathlib import Path
import sys
from email_risk_analyzer import analyze_file

def build_text(path, result):
    lines = [
        "EMAIL SECURITY AUDIT REPORT",
        "=" * 70,
        f"File: {path.name}",
        f"Risk level: {result['risk_level']}",
        f"Risk score: {result['risk_score']}/100",
        "",
        "Purpose",
        "This report is for defensive cybersecurity training. It analyzes only the",
        "supplied synthetic email and does not follow links or contact external systems.",
        "",
        "Header summary",
        f"From: {result['headers']['From']}",
        f"Reply-To: {result['headers']['Reply-To'] or '(none)'}",
        f"Return-Path: {result['headers']['Return-Path'] or '(none)'}",
        f"Subject: {result['headers']['Subject']}",
        f"Received headers: {result['headers']['Received_Count']}",
        "",
        "Detected indicators",
    ]
    if not any(f["points"] for f in result["findings"]):
        lines.append("- No scored indicators detected.")
    for f in result["findings"]:
        if f["points"]:
            lines.append(f"- +{f['points']} | {f['category']} | {f['evidence']}")
            lines.append(f"  Recommendation: {f['recommendation']}")
    lines += [
        "",
        "URLs extracted (not opened)",
        *([f"- {u}" for u in result["urls_found"][:10]] or ["- None"]),
        "",
        "Attachments detected",
        *([f"- {a}" for a in result["attachments"]] or ["- None"]),
        "",
        "Conclusion",
        result["summary"],
        "",
        "Important: A score is a triage aid, not a verdict. SPF/DKIM passing does",
        "not guarantee safety, and a failed authentication check can have benign causes.",
    ]
    return "\n".join(lines)

def make_pdf(text, output):
    from fpdf import FPDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Email Security Audit Report", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for line in text.splitlines():
        if line.startswith("===="):
            pdf.ln(2)
            continue
        safe = line.encode("latin-1", "replace").decode("latin-1")
        if line and not line.startswith(" "):
            pdf.multi_cell(0, 5, safe)
        else:
            pdf.multi_cell(0, 5, safe)
    pdf.output(str(output))

def main():
    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    files = sorted(Path("sample_emails").glob("*.eml"))
    if not files:
        print("No .eml samples found.")
        sys.exit(1)

    combined = []
    for f in files:
        result = analyze_file(f)
        text = build_text(f, result)
        output = out_dir / f"{f.stem}_audit.pdf"
        make_pdf(text, output)
        combined.append(text)

    combined_pdf = out_dir / "Phishing_Analysis_Report.pdf"
    make_pdf("\n\n".join(combined), combined_pdf)
    print(f"Generated: {combined_pdf}")

if __name__ == "__main__":
    main()
