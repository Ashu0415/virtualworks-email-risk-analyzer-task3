import re

PHISHING_KEYWORDS = [
    "urgent", "verify your account", "suspended", "immediately",
    "click here", "update your payment", "unauthorized login",
    "confirm your identity", "password reset", "limited time",
    "act now", "won a prize", "claim your reward", "bank details"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".zip", ".iso", ".apk"
]


def analyze_email(subject, body):
    score = 0
    flags = []
    combined_text = f"{subject} {body}".lower()

    # 1. Check for High-Risk Phishing Keywords
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in combined_text]
    if matched_keywords:
        score += min(len(matched_keywords) * 2, 6)
        flags.append(f"Suspicious urgency/phishing phrases detected: {', '.join(matched_keywords)}")

    # 2. Check for URLs and IP-Based Links
    urls = re.findall(r"https?://[^\s]+", body)
    if urls:
        score += 1
        flags.append(f"Contains {len(urls)} external link(s) - verify domain authenticity before clicking.")
        for url in urls:
            if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
                score += 3
                flags.append(f"High-risk IP-based URL detected: {url}")
            if "http://" in url.lower():
                score += 1
                flags.append(f"Unencrypted HTTP link detected: {url}")

    # 3. Check for Sensitive Information Requests
    if re.search(r"\b(password|otp|ssn|credit card|pin|cvv|bank account)\b", combined_text):
        score += 3
        flags.append("Requests sensitive credentials or financial information.")

    # 4. Check for Dangerous Attachment Mentions
    matched_exts = [ext for ext in SUSPICIOUS_EXTENSIONS if ext in combined_text]
    if matched_exts:
        score += 3
        flags.append(f"Mentions potentially hazardous file extension(s): {', '.join(matched_exts)}")

    # Classify Risk Level
    if score == 0:
        risk_level = "Low Risk (Appears Safe)"
    elif score <= 4:
        risk_level = "Moderate Risk (Review Carefully)"
    else:
        risk_level = "High Risk (Likely Phishing)"

    return risk_level, score, flags


def main():
    print("=== Email Risk Analyzer ===")
    subject = input("Enter Email Subject: ").strip()
    print("Enter Email Body (type 'END' on a new line when finished):")

    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)

    body = "\n".join(lines).strip()

    if not subject and not body:
        print("Error: Email subject and body cannot both be empty.")
        return

    risk_level, score, flags = analyze_email(subject, body)

    print(f"\nRisk Assessment: {risk_level} (Risk Score: {score})")
    if flags:
        print("\nDetected Indicators:")
        for flag in flags:
            print(f"- {flag}")
    else:
        print("\nNo common phishing indicators were detected.")


if __name__ == "__main__":
    main()
