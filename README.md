# LeakLens – Local PII & Secrets Guardian for AI Prompts

**Protect sensitive information in Arabic and English prompts before they reach AI tools.**


LeakLens is a browser-integrated privacy layer built during an AI hackathon. It detects PII (names, phone numbers, emails, IDs), secrets (API keys, database credentials, passwords), and sensitive content in real time, letting users **warn**, **redact**, or **block** risky prompts.

---

## Problem Statement

Users often paste real customer messages into AI tools, creating serious privacy risks. LeakLens ensures sensitive data **never leaves the browser** accidentally.

---

## Features

* **Layered Detection**: Regex, secret scanner, Arabic NER, spaCy for English.
* **Policy Enforcement**:

  * `warn` – alerts the user but allows submission.
  * `redact` – replaces sensitive values while keeping the text usable.
  * `block` – stops high-risk text from being submitted.
* **Multi-language Support**: Arabic + English PII detection.
* **Extensible**: Add new detection rules or datasets easily.

---

## Installation & Setup (Detailed)

### 1. Clone the Repo

```bash
git clone https://github.com/Amal-Alassaf/LeakLens.git
cd LeakLens
```

### 2. Create & Activate Virtual Environment

```bash
# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Download the Arabic GLiNER Model

```bash
git clone https://huggingface.co/NAMAA-Space/gliner_arabic-v2.1 models/gliner_arabic
```

> This step is required because the model is not included in the repo due to size.

### 5. Run the Backend

```bash
python -m uvicorn backend.api.main:app --reload
```

### 6. Serve the Web Demo

```bash
cd demo-web
py -3.11 -m http.server 5500
```

### 7. Load the Browser Extension

1. Open `chrome://extensions/` in Chrome/Edge
2. Enable **Developer Mode**
3. Load the `extension/` folder


### 4. Using LeakLens with ChatGPT

1. Open `https://chatgpt.com/`.
2. Ensure the extension is enabled.
3. Paste text prompts into the input box; LeakLens will automatically scan based on the selected policy (**warn**, **redact**, **block**).

---

## Example Inputs

### Arabic (multi-PII)

```text
مرحبًا، أنا سارة العبدالله. رقمي +966501234567 وبريدي sara.alabdullah@example.com. استخدمت مؤقتًا api_key = "abc1234567890SECRETKEY" وقاعدة البيانات DATABASE_URL=postgresql://appuser:dbpass123@localhost:5432/leaklens_db
```

### English (multi-PII)

```text
My name is Sarah Johnson. Email: sarah@example.com. Phone: +966501234567. Temporary password: TempPass2026##
```

### Payment / Credit Card

```text
Customer payment: card 4111111111111111, email billing@example.com, phone +966501112233.
```

---

## Evaluation & Test Bank

LeakLens includes a curated test bank: `tools/demo_test_bank.json`

Run evaluation:

```bash
python -m tools.run_demo_test_bank
```

This produces precision, recall, and F1 metrics for each PII type.

---

## Directory Overview

```text
backend/      # Scanner logic & API
demo-web/     # Web interface
extension/    # Browser extension (Chrome/Edge)
models/       # Pretrained Arabic GLiNER NER model (not included)
tools/        # Scripts, payloads, test bank
docs/         # Architecture notes, demo guide
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
* **Hackathon-ready**: Clean demo flow for LinkedIn sharing.

---

## Model Instructions

The Arabic GLiNER model is loaded locally from `models/gliner_arabic`. It is **not included** in the repository due to size.

```bash
git clone https://huggingface.co/NAMAA-Space/gliner_arabic-v2.1 models/gliner_arabic
```

---

## License

MIT License. See [LICENSE](LICENSE).
