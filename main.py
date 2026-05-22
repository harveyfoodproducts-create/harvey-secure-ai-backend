from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression

import requests
import re
from urllib.parse import urlparse

# ======================================================
# FASTAPI APP
# ======================================================

app = FastAPI()

# ======================================================
# CORS SUPPORT
# ======================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================================================
# INPUT MODELS
# ======================================================

class InputData(BaseModel):
    text: str

class NumberCheck(BaseModel):
    number: str

# ======================================================
# SPAM NUMBER DATABASE
# ======================================================

spam_numbers = {
    "9876543210": "Loan scam",
    "9123456780": "Bank fraud",
    "9000000000": "Lottery scam",
    "8888888888": "UPI phishing",
}

# ======================================================
# TRAINING DATA
# ======================================================

texts = [

    # Scam
    "your bank account blocked click link",
    "win money now click here",
    "urgent verify account",
    "free gift claim now",
    "lottery winner claim now",
    "click here to get reward",
    "upi suspended verify immediately",
    "your atm blocked update kyc",
    "your otp expired verify now",
    "send bank details immediately",
    "claim cashback reward now",
    "download apk now",
    "your account will be suspended",
    "click here to verify kyc",
    "bank account frozen verify now",
    "telegram investment opportunity",
    "crypto investment guaranteed return",
    "refund pending verify account",
    "wallet verification required",

    # Safe
    "meeting at 5pm",
    "call me later",
    "project meeting tomorrow",
    "family dinner tonight",
    "https://google.com",
    "hello how are you",
    "invoice approved successfully",
    "office work completed",
    "thank you",
    "please review the document",
]

labels = [
    1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,
    0,0,0,0,0,0,0,0,0,0
]

# ======================================================
# ML MODEL
# ======================================================

vectorizer = CountVectorizer(
    ngram_range=(1, 2)
)

X = vectorizer.fit_transform(texts)

model = LogisticRegression(
    max_iter=1000
)

model.fit(X, labels)

# ======================================================
# RISK KEYWORDS
# ======================================================

HIGH_RISK_KEYWORDS = [
    "otp",
    "verify",
    "bank",
    "login",
    "crypto",
    "bitcoin",
    "free",
    "gift",
    "winner",
    "claim",
    "upi",
    "suspended",
    "kyc",
    "reward",
    "apk",
    "cashback",
    "password",
    "wallet",
    "transfer",
    "refund",
    "telegram",
    "investment",
    "guaranteed",
    "urgent",
    "blocked",
]

SUSPICIOUS_DOMAINS = [
    "bit.ly",
    "tinyurl",
    "rb.gy",
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

# ======================================================
# HOME
# ======================================================

@app.get("/")
def home():

    return {
        "message": "Harvey Secure AI Backend Running 🚀"
    }

# ======================================================
# HEALTH
# ======================================================

@app.get("/health")
def health():

    return {
        "status": "running"
    }

# ======================================================
# URL EXTRACTION
# ======================================================

def extract_urls(text):

    pattern = r"(https?://[^\s]+)"

    return re.findall(pattern, text)

# ======================================================
# URL ANALYSIS
# ======================================================

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
                    f"Suspicious shortened URL: {domain}"
                )

        if "@" in url:

            risk += 20

            findings.append(
                "URL contains @ symbol"
            )

        if domain.count("-") >= 3:

            risk += 20

            findings.append(
                "Suspicious domain structure"
            )

    return risk, findings

# ======================================================
# KEYWORD ANALYSIS
# ======================================================

def keyword_analysis(text):

    text = text.lower()

    risk = 0

    findings = []

    for keyword in HIGH_RISK_KEYWORDS:

        if keyword in text:

            risk += 10

            findings.append(
                f"Keyword detected: {keyword}"
            )

    return risk, findings

# ======================================================
# PHISHING DETECTION
# ======================================================

def phishing_detection(text):

    text_lower = text.lower()

    risk = 0

    findings = []

    urls = extract_urls(text)

    for bank in BANK_NAMES:

        if bank in text_lower and len(urls) > 0:

            risk += 25

            findings.append(
                f"Possible phishing targeting {bank}"
            )

    return risk, findings

# ======================================================
# AI PATTERN ANALYSIS
# ======================================================

def ai_prompt_analysis(text):

    patterns = [
        r"click.*link",
        r"verify.*account",
        r"urgent.*action",
        r"send.*otp",
        r"claim.*reward",
        r"limited.*offer",
    ]

    risk = 0

    findings = []

    for pattern in patterns:

        if re.search(pattern, text.lower()):

            risk += 10

            findings.append(
                f"Suspicious behavior pattern: {pattern}"
            )

    return risk, findings

# ======================================================
# SAFE BROWSING CHECK
# ======================================================

def google_safe_browsing_check(url):

    try:

        api_url = (
            "https://safebrowsing.googleapis.com/v4/"
            "threatMatches:find"
        )

        payload = {
            "client": {
                "clientId": "harvey_secure_ai",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": [
                    "ANY_PLATFORM"
                ],
                "threatEntryTypes": [
                    "URL"
                ],
                "threatEntries": [
                    {
                        "url": url
                    }
                ]
            }
        }

        response = requests.post(
            api_url,
            json=payload,
            timeout=10
        )

        data = response.json()

        return "matches" in data

    except Exception:

        return False

# ======================================================
# SCAN API
# ======================================================

@app.post("/scan")
def scan(data: InputData):

    text = data.text.lower()

    total_risk = 0

    findings = []

    # ==================================================
    # URL ANALYSIS
    # ==================================================

    urls = extract_urls(text)

    url_risk, url_findings = analyze_urls(urls)

    total_risk += url_risk

    findings.extend(url_findings)

    # ==================================================
    # KEYWORD ANALYSIS
    # ==================================================

    keyword_risk, keyword_findings = keyword_analysis(text)

    total_risk += keyword_risk

    findings.extend(keyword_findings)

    # ==================================================
    # PHISHING DETECTION
    # ==================================================

    phishing_risk, phishing_findings = phishing_detection(text)

    total_risk += phishing_risk

    findings.extend(phishing_findings)

    # ==================================================
    # AI PATTERN ANALYSIS
    # ==================================================

    ai_risk, ai_findings = ai_prompt_analysis(text)

    total_risk += ai_risk

    findings.extend(ai_findings)

    # ==================================================
    # MACHINE LEARNING ANALYSIS
    # ==================================================

    X_input = vectorizer.transform([text])

    prediction = model.predict(X_input)[0]

    probability = model.predict_proba(X_input)[0][1]

    ml_score = int(probability * 100)

    if prediction == 1:

        total_risk += ml_score

        findings.append(
            "Machine learning detected scam behavior"
        )

    # ==================================================
    # LIMIT SCORE
    # ==================================================

    if total_risk > 100:

        total_risk = 100

    # ==================================================
    # FINAL ANALYSIS
    # ==================================================

    if total_risk >= 80:

        analysis = "🚨 HIGH RISK SCAM"

    elif total_risk >= 40:

        analysis = "⚠️ MEDIUM RISK"

    else:

        analysis = "✅ LOW RISK"

    return {
        "analysis": analysis,
        "score": total_risk,
        "findings": findings,
        "urls_detected": urls,
    }

# ======================================================
# CALLER REPUTATION
# ======================================================

@app.post("/check-number")
def check_number(data: NumberCheck):

    number = data.number.strip()

    clean_number = (
        number
        .replace("+91", "")
        .replace(" ", "")
    )

    if clean_number in spam_numbers:

        return {
            "result": "🚨 Spam Caller Detected",
            "reason": spam_numbers[clean_number],
            "risk": 95
        }

    return {
        "result": "✅ Safe Number",
        "reason": "No complaints found",
        "risk": 10
    }