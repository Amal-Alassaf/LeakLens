Got it. Based on your style preference (step-by-step, clear, no screenshots), here’s a full `docs/demo-guide.md` draft for LeakLens that aligns with your current README structure and is LinkedIn-ready:

---

# LeakLens Demo Guide

## Introduction

This guide walks you through running LeakLens locally and testing its PII and secret detection capabilities in both Arabic and English. LeakLens helps prevent sensitive data from leaving your machine when interacting with AI tools.

---

## Backend Setup

1. **Create a virtual environment**

```bash
python -m venv .venv
```

2. **Activate the environment**

* **Linux/macOS**:

```bash
source .venv/bin/activate
```

* **Windows**:

```bash
.venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Run the FastAPI server**

```bash
python -m uvicorn backend.api.main:app --reload
```

Open your browser at:

```
http://127.0.0.1:8000
```

---

## Web Interface

1. Open the demo page:

```
demo-web/index.html
```

2. Paste a sample text prompt.

3. Select a policy:

* **warn** – alerts the user of sensitive content.
* **redact** – replaces sensitive content while keeping text usable.
* **block** – prevents submission of high-risk content.

4. Click **Scan** to see the processed output and risk summary.

---

## Browser Extension

1. Load the `extension/` folder in Chrome or Edge developer mode.

2. Pin the extension to the toolbar.

3. Paste text in any AI tool input box; LeakLens will automatically scan before submission.

---

## Example Inputs

### Arabic

```text
مرحبًا، أنا سارة العبدالله. رقمي +966501234567 وبريدي sara.alabdullah@example.com. استخدمت مؤقتًا api_key = "abc1234567890SECRETKEY" وقاعدة البيانات DATABASE_URL=postgresql://appuser:dbpass123@localhost:5432/leaklens_db
```

### English

```text
My name is Sarah Johnson. Email: sarah@example.com. Phone: +966501234567. Temporary password: TempPass2026##
```

### Payment / Credit Card

```text
Customer payment: card 4111111111111111, email billing@example.com, phone +966501112233.
```

---

## Evaluation & Test Bank

1. LeakLens includes a curated **test bank**:

```bash
tools/demo_test_bank.json
```

2. It covers:

* Names, emails, phones
* IDs, passports, credit cards
* Passwords and API keys
* Database credentials
* Safe texts for false-positive testing

3. Run evaluation:

```bash
python -m tools.run_demo_test_bank
```

This will produce precision, recall, and F1 metrics for each PII type.

---

## Directory Overview

```
backend/      # Scanner logic & API
demo-web/     # Web interface
extension/    # Browser extension (Chrome/Edge)
models/       # Pretrained Arabic GLiNER NER model (not included)
tools/        # Scripts, payloads, test bank
docs/         # Optional architecture notes, demo guide
README.md
requirements.txt
.gitignore
LICENSE
```

---

## Notes

* **Local-first**: No sensitive text leaves your machine.
* **Extensible**: Add new PII types or policies in `backend/scanner`.
* **Arabic support**: NER model tuned for Arabic, with false-positive filters.
* **Hackathon-ready**: Clear demo flow for LinkedIn sharing.

---

## Model Instructions

The Arabic GLiNER model is loaded locally from `models/gliner_arabic`. It is **not included** in the repository due to size. To download:

```bash
git clone https://huggingface.co/NAMAA-Space/gliner_arabic-v2.1 models/gliner_arabic
```

---
