# LeakLens

A privacy protection layer that scans user input for personally identifiable information (PII) **before** it reaches any AI model. Built for the AI Hackathon — Cybersecurity & AI Track.

---

## What it does

Every day, users accidentally paste passwords, national IDs, credit card numbers, and medical details into AI chatbots. PII Guardian sits between the user and the AI, intercepts the message, and either blocks it, redacts the sensitive parts, or warns the user — before any data leaves.

```
User types message
       ↓
PII Guardian scans it  ←─── three layers: regex + spaCy NER + Claude AI
       ↓
Policy applied (block / redact / warn / strict)
       ↓
Clean, safe text forwarded to the AI model
```

---

## Detection layers

| Layer | Method | What it catches |
|-------|--------|----------------|
| 1 | Regex rules | Emails, Saudi phone numbers, national IDs, credit cards, passwords, IP addresses, passports, dates of birth |
| 2 | spaCy NER model | Person names, organizations, locations, financial mentions |
| 3 | Claude AI (optional) | Contextual and Arabic PII that rules and models miss |

---

## PII types detected

| Type | Severity | Example |
|------|----------|---------|
| Email | Medium | ahmed@example.com |
| Saudi phone | Medium | 0501234567 / +966501234567 |
| National ID / Iqama | High | 1098765432 |
| Credit card | High | 4532015112830366 |
| Password | High | password: abc123 |
| IP address | Medium | 192.168.1.1 |
| Passport | High | passport: A1234567 |
| Date of birth | Low | DOB: 01/01/1990 |
| Person name | Low | My name is Ahmed Ali |
| Organization | Low | I work at Saudi Aramco |
| Location | Low | I live in Al-Malaz, Riyadh |

Arabic input is supported for passwords, names, and dates.

---

## Quick start

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/LeakLens.git
cd LeakLens
```

### 2. Install Python 3.11

This project requires **Python 3.11** (not 3.12+ or 3.14).
Download it from: https://www.python.org/downloads/release/python-3119/

Verify your installation:
```bash
py -3.11 --version
```

### 3. Install dependencies

```bash
py -3.11 -m pip install -r requirements.txt
```

### 4. Install the spaCy NER model

```bash
py -3.11 -m spacy download en_core_web_sm
```

### 5. Run the tests

```bash
py -3.11 -m backend.tests.test_scanner
```

Expected output: `10/10 tests passed`

### 6. Start the API server

```bash
py -3.11 -m uvicorn backend.api.main:app --reload
```

Server runs at: `http://127.0.0.1:8000`

### 7. Open the live demo

Open `demo.html` directly in your browser — no extra setup needed.

Or open the interactive API docs at: `http://127.0.0.1:8000/docs`

---

## API usage

### Scan text

```
POST http://127.0.0.1:8000/scan
Content-Type: application/json
```

**Request body:**
```json
{
  "text": "My email is ahmed@example.com and my ID is 1098765432",
  "policy": "redact",
  "use_ai": false
}
```

**Policies:**
| Policy | Behavior |
|--------|----------|
| `warn` | Forward original text, flag detections |
| `redact` | Replace PII with placeholders, forward clean text |
| `block` | Reject the message entirely |
| `strict` | Block HIGH, redact MEDIUM, warn LOW severity |

**Response:**
```json
{
  "is_safe": false,
  "action_taken": "redacted",
  "risk_score": 0.715,
  "output_text": "My email is [EMAIL REDACTED] and my ID is [NATIONAL ID REDACTED]",
  "summary": "Detected: email, national_id",
  "ai_enhanced": false,
  "detections": [
    {
      "pii_type": "email",
      "value": "ahmed@example.com",
      "redacted": "[EMAIL REDACTED]",
      "severity": "medium",
      "confidence": 0.97,
      "explanation": "Email address found",
      "source": "regex"
    }
  ]
}
```

### Enable AI layer (optional)

Pass your Anthropic API key as a header to activate the Claude NER layer:

```
POST /scan
x-api-key: sk-ant-...
Content-Type: application/json

{ "text": "...", "policy": "redact", "use_ai": true }
```

---

## Project structure

```
LeakLens/
├── backend/
│   ├── scanner/
│   │   ├── detector.py      # Core regex engine — 9 PII types
│   │   ├── spacy_ner.py     # spaCy NER layer — names, orgs, locations
│   │   ├── ai_ner.py        # Claude AI layer — contextual + Arabic PII
│   │   └── policy.py        # Policy engine — block / redact / warn / strict
│   ├── api/
│   │   └── main.py          # FastAPI REST endpoint
│   └── tests/
│       └── test_scanner.py  # 10 test cases
├── demo.html                # Live demo UI (open in browser)
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.11
- fastapi
- uvicorn
- httpx
- pydantic
- spacy + en_core_web_sm

See `requirements.txt` for pinned versions.

---

## Built at

AI Hackathon — Cybersecurity & AI Track
May 2025
