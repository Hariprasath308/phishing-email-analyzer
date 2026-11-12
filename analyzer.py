

from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re

EMAIL_FILE = Path("samples/sample_email.txt")
REPORT_FILE = Path("reports/phishing_report.txt")

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "verification",
    "password",
    "account suspended",
    "click here",
    "update your account",
    "bank details",
    "immediately",
    "security alert",
    "confirm your identity"
]


def analyze_email():
    if not EMAIL_FILE.exists():
        print("[ERROR] Sample email not found!")
        return

    raw_email = EMAIL_FILE.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    email_text = raw_email.decode("utf-8", errors="replace").lower()
    findings = []

    # Keyword detection
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in email_text:
            findings.append(f"Suspicious keyword: {keyword}")

    # Sender detection
    _, from_address = parseaddr(message.get("From", ""))
    _, reply_address = parseaddr(message.get("Reply-To", ""))

    if not from_address:
        findings.append("Missing or invalid sender address")

    # Reply-To comparison
    if reply_address and from_address:
        from_domain = from_address.split("@")[-1].lower()
        reply_domain = reply_address.split("@")[-1].lower()

        if from_domain != reply_domain:
            findings.append("From and Reply-To domains do not match")

    # URL detection
    urls = re.findall(r'https?://[^\s<>"\']+', email_text)

    if urls:
        findings.append(f"URLs found: {len(urls)}")

    # Risk assessment
    score = len(findings)

    if score >= 4:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # Report
    report = [
        "PHISHING EMAIL ANALYSIS REPORT",
        "=" * 35,
        f"Email analyzed: {EMAIL_FILE}",
        f"Sender: {from_address or 'Not available'}",
        f"Reply-To: {reply_address or 'Not available'}",
        f"URLs found: {len(urls)}",
        f"Detection findings: {score}",
        f"Risk Level: {risk}",
        "",
        "DETECTION FINDINGS",
        "-" * 35
    ]

    if findings:
        for finding in findings:
            report.append(f"[WARNING] {finding}")
    else:
        report.append("No suspicious indicators found.")

    report.extend([
        "",
        "URL INDICATORS",
        "-" * 35
    ])

    if urls:
        for url in urls:
            report.append(f"[CHECK] {url}")
    else:
        report.append("No URLs found.")

    report.extend([
        "",
        "Note: This is a basic educational analyzer.",
        "Warnings are indicators, not proof of phishing.",
        "Detected links are listed only and never opened."
    ])

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text("\n".join(report) + "\n", encoding="utf-8")

    print("\n".join(report))
    print(f"\n[+] Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    analyze_email()
