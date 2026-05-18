
# LeakLens

LeakLens is a local privacy scanner that detects PII before a message or file is sent to an AI/chat flow.

It can **warn**, **redact**, or **block** sensitive content.

## Features

- Text scanning
- File scanning: `.txt`, `.pdf`
- Demo chat page
- Browser extension flow
- Regex detection
- spaCy NER detection
- Arabic NER integration
- Offline model support

## Detected PII

- Email
- Phone number
- National ID / Iqama
- Passport
- Credit card
- Date of birth
- IP address
- Password
- Person name
- Organization
- Location

## Requirements

- Python 3.11
- Git
- Node not required for the demo page

## Setup

Clone the repository:

```bash
git clone https://github.com/Amal-Alassaf/LeakLens.git
cd LeakLens
````

Create and activate a virtual environment:

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bash
py -3.11 -m pip install -r requirements.txt
```

Install the spaCy model:

```bash
python -m spacy download en_core_web_sm
```

## Run the backend

From the project root:

```bash
python -m uvicorn backend.api.main:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

API docs:

```text
http://127.0.0.1:8000/docs
```

## Run the demo page

Open a second terminal:

```bash
cd demo-web
python -m http.server 5500
```

Open:

```text
http://127.0.0.1:5500
```

## Test commands

Check backend health:

```bash
curl http://127.0.0.1:8000/health
```

Scan text:

```bash
curl -X POST http://127.0.0.1:8000/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"text\":\"My email is ahmed@test.com and my ID is 1098765432\",\"policy\":\"redact\"}"
```

Run scanner tests:

```bash
py -3.11 -m backend.tests.test_scanner
```

## Policies

| Policy   | Behavior                                            |
| -------- | --------------------------------------------------- |
| `warn`   | Allows the content but shows a warning              |
| `redact` | Replaces sensitive values with masked/redacted text |
| `block`  | Blocks the message or file content                  |

## Project structure

```text
LeakLens/
├── backend/
│   ├── api/
│   │   └── main.py
│   └── scanner/
│       ├── detector.py
│       ├── spacy_ner.py
│       └── arabic_ner.py
├── demo-web/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── extension/
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
├── tools/
├── requirements.txt
└── README.md
```

## Notes

The local model folder is ignored by Git. Download or place offline models locally when needed.

## Built for

AI Hackathon — Cybersecurity & AI Track
