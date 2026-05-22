import re
from urllib.parse import urlparse

HIGH_RISK_KEYWORDS = [
    "otp",
    "verify account",
    "bank update",
    "urgent action",
    "click here",
    "free money",
    "investment",
    "bitcoin profit",
    "loan approval",
    "credit card blocked",
    "reward claim",
    "lottery",
    "winner",
    "kyc update",
    "income tax refund",
    "upi blocked",
    "send money",
    "gift card",
    "telegram job",
    "work from home",
]

MEDIUM_RISK_KEYWORDS = [
    "offer",
    "discount",
    "limited time",
    "promo",
    "bonus",
    "coupon",
    "download app",
    "verify mobile",
]

SUSPICIOUS_DOMAINS = [
    "bit.ly",
    "tinyurl",
    "rb.gy",
    "t.co",
    "grabify",
]

BANK_NAMES = [
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "kotak",
    "paypal",
    "phonepe",
    "paytm",
    "gpay",
]

def extract_urls(text):
    url_pattern = r"(https?://[^\s]+)"
    return re.findall(url_pattern, text)

def analyze_urls(urls):
    risk = 0
    findings = []

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        for suspicious in SUSPICIOUS_DOMAINS:
            if suspicious in domain:
                risk += 35
                findings.append(
                    f"Suspicious shortened URL detected: {domain}"
                )

        if "@" in url:
            risk += 20
            findings.append(
                "URL contains @ symbol"
            )

        if domain.count("-") >= 3:
            risk += 20
            findings.append(
                "Highly suspicious domain structure"
            )

    return risk, findings

def keyword_analysis(text):
    text_lower = text.lower()

    risk = 0
    findings = []

    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in text_lower:
            risk += 15
            findings.append(
                f"High-risk keyword detected: {keyword}"
            )

    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in text_lower:
            risk += 7
            findings.append(
                f"Medium-risk keyword detected: {keyword}"
            )

    return risk, findings

def phishing_detection(text):
    text_lower = text.lower()

    risk = 0
    findings = []

    urls = extract_urls(text)

    for bank in BANK_NAMES:
        if bank in text_lower and len(urls) > 0:
            risk += 25
            findings.append(
                f"Possible phishing attempt targeting {bank}"
            )

    return risk, findings

def ai_prompt_analysis(text):
    risk = 0
    findings = []

    suspicious_patterns = [
        r"click.*link",
        r"verify.*account",
        r"urgent.*action",
        r"send.*otp",
        r"claim.*reward",
        r"limited.*offer",
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, text.lower()):
            risk += 10
            findings.append(
                f"Suspicious behavioral pattern: {pattern}"
            )

    return risk, findings

def ml_scoring(total_risk):
    if total_risk >= 80:
        return "🚨 HIGH RISK SCAM"

    if total_risk >= 40:
        return "⚠ MEDIUM RISK"

    return "✅ LOW RISK"

def analyze_text(text):
    total_risk = 0
    all_findings = []

    urls = extract_urls(text)

    url_risk, url_findings = analyze_urls(urls)
    total_risk += url_risk
    all_findings.extend(url_findings)

    keyword_risk, keyword_findings = keyword_analysis(text)
    total_risk += keyword_risk
    all_findings.extend(keyword_findings)

    phishing_risk, phishing_findings = phishing_detection(text)
    total_risk += phishing_risk
    all_findings.extend(phishing_findings)

    ai_risk, ai_findings = ai_prompt_analysis(text)
    total_risk += ai_risk
    all_findings.extend(ai_findings)

    if total_risk > 100:
        total_risk = 100

    final_result = ml_scoring(total_risk)

    return {
        "score": total_risk,
        "analysis": final_result,
        "findings": all_findings,
    }