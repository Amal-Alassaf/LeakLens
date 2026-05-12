# PII Guardian — Day 1 Prototype

Scans user input for personally identifiable information before it reaches an AI model.

## Quick start

### 1. Install dependencies
Open a terminal inside this folder and run:
```
pip install -r requirements.txt
```

### 2. Run the tests
```
python -m backend.tests.test_scanner
```
Expected: 10/10 tests passed ✓

### 3. Start the API server
```
uvicorn backend.api.main:app --reload
```

### 4. Open the interactive docs
Go to: http://127.0.0.1:8000/docs

Click POST /scan → "Try it out" → paste any text and choose a policy (block / redact / warn).

---

## PII types detected
| Type | Severity | Example |
|------|----------|---------|
| Email | Medium | ahmed@example.com |
| Saudi phone | Medium | 0501234567 |
| National ID / Iqama | High | 1098765432 |
| Credit card | High | 4532015112830366 |
| Password | High | password: abc123 |
| IP address | Medium | 192.168.1.1 |
| Passport | High | passport: A1234567 |
| Date of birth | Low | DOB: 01/01/1990 |
| Person name | Low | My name is Ahmed Ali |

Arabic input is supported for passwords and names.

## API usage example
```
POST /scan
{
  "text": "My email is test@example.com and my ID is 1098765432",
  "policy": "redact"
}
```
Response:
```json
{
  "is_safe": false,
  "action_taken": "redacted",
  "output_text": "My email is [EMAIL REDACTED] and my ID is [NATIONAL ID REDACTED]",
  "risk_score": 0.715,
  "detections": [...]
}
```
