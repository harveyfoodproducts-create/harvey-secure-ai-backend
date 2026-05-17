from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression

from openai import OpenAI

import requests
import re
import os

# ======================================================
# FASTAPI APP
# ======================================================

app = FastAPI()

# ======================================================
# CORS SUPPORT FOR FLUTTER
# ======================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================================================
# OPENAI API KEY
# ======================================================

# SET YOUR OPENAI API KEY HERE
OPENAI_API_KEY = "YOUR_OPENAI_API_KEY"

client = OpenAI(
    api_key=OPENAI_API_KEY
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
# AI TRAINING DATA
# ======================================================

texts = [

    # Scam Messages
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

    # Phishing URLs
    "http://fake-bank-login.xyz",
    "https://verify-otp-now.com",
    "click phishing link now",
    "crypto giveaway free bitcoin",
    "upi account suspended verify now",

    # Safe Messages
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
    1,1,1,1,1,
    0,0,0,0,0,0,0,0,0,0
]

# ======================================================
# TRAIN MACHINE LEARNING MODEL
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
# HOME ROUTE
# ======================================================

@app.get("/")
def home():

    return {
        "message": "Harvey Secure AI Backend Running 🚀"
    }

# ======================================================
# HEALTH CHECK
# ======================================================

@app.get("/health")
def health():

    return {
        "status": "running"
    }

# ======================================================
# URL DETECTION
# ======================================================

def contains_url(text):

    url_pattern = r"(https?://[^\s]+)"

    return re.search(url_pattern, text)

# ======================================================
# GOOGLE SAFE BROWSING
# ======================================================

GOOGLE_SAFE_BROWSING_KEY = "fd95516e1a9ed3bf8b6d84ab77ee75b29cccdb6c9534051dc998a8c2c05875a2"

def google_safe_browsing_check(url):

    try:

        api_url = (
            "https://safebrowsing.googleapis.com/v4/"
            f"threatMatches:find?key={fd95516e1a9ed3bf8b6d84ab77ee75b29cccdb6c9534051dc998a8c2c05875a2}"
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
            timeout=15
        )

        data = response.json()

        if "matches" in data:
            return True

        return False

    except Exception:
        return False

# ======================================================
# OLLAMA AI ANALYSIS
# ======================================================

def ollama_analysis(text):

    try:

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "phi3",
                "prompt": f"""
You are a cybersecurity AI.

Analyze this message for:
- scam
- phishing
- fraud
- malicious intent
- social engineering

Message:
{text}

Reply with:
1. Risk level
2. Reason
3. Threat type
4. Recommended action
""",
                "stream": False
            },
            timeout=20
        )

        data = response.json()

        return data.get("response", "")

    except Exception as e:

        return f"Ollama AI unavailable: {str(e)}"

# ======================================================
# OPENAI ANALYSIS
# ======================================================

def openai_analysis(text):

    try:

        response = client.chat.completions.create(

            model="gpt-4.1-mini",

            messages=[

                {
                    "role": "system",
                    "content": """
You are a cybersecurity AI.

Analyze messages for:
- scams
- phishing
- fraud
- impersonation
- malicious intent
- social engineering
"""
                },

                {
                    "role": "user",
                    "content": text
                }
            ]
        )

        return response.choices[0].message.content

    except Exception as e:

        return f"OpenAI unavailable: {str(e)}"

# ======================================================
# AI SCAN API
# ======================================================

@app.post("/scan")
def scan(data: InputData):

    text = data.text.lower()

    suspicious_keywords = [
        "verify",
        "otp",
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
        "support",
        "telegram",
        "investment",
        "guaranteed",
        "urgent",
        "blocked",
        "account",
    ]

    # ======================================================
    # URL PHISHING CHECK
    # ======================================================

    if contains_url(text):

        for word in suspicious_keywords:

            if word in text:

                safe_browsing = google_safe_browsing_check(text)

                return {
                    "analysis": "🚨 High Risk Phishing URL Detected",
                    "score": 95,
                    "type": "phishing",
                    "google_safe_browsing": safe_browsing,
                    "ai_analysis": "Suspicious phishing URL detected"
                }

    # ======================================================
    # MACHINE LEARNING DETECTION
    # ======================================================

    X_input = vectorizer.transform([text])

    prediction = model.predict(X_input)[0]

    probability = model.predict_proba(X_input)[0][1]

    score = int(probability * 100)

    # ======================================================
    # OLLAMA ANALYSIS
    # ======================================================

    ollama_result = ollama_analysis(text)

    # ======================================================
    # OPENAI ANALYSIS
    # ======================================================

    openai_result = openai_analysis(text)

    # ======================================================
    # FINAL RESPONSE
    # ======================================================

    if prediction == 1:

        return {
            "analysis": "🚨 AI detected possible scam",
            "score": max(score, 75),
            "type": "spam",
            "ollama_analysis": ollama_result,
            "openai_analysis": openai_result
        }

    else:

        return {
            "analysis": "✅ Message appears safe",
            "score": 15,
            "type": "safe",
            "ollama_analysis": ollama_result,
            "openai_analysis": openai_result
        }

# ======================================================
# CALLER REPUTATION CHECK
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

    else:

        return {
            "result": "✅ Safe Number",
            "reason": "No complaints found",
            "risk": 10
        }