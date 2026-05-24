
# LeakLens

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-green)](https://fastapi.tiangolo.com/)
[![Security](https://img.shields.io/badge/Privacy-Local--First-red)](https://github.com/QuantumDevPro/LeakLens)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

A **local PII and secrets guardian** for Arabic and English AI prompts.

LeakLens detects sensitive information before it reaches AI tools, including names, emails, phone numbers, IDs, passwords, API keys, database URLs, and other secrets.

It supports three policies:

* `warn` — alert the user before submitting
* `redact` — hide sensitive values while keeping the prompt usable
* `block` — stop risky prompts from being submitted

---

# Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Obtain the Project](#obtain-the-project)
- [Install Dependencies](#install-dependencies)
- [Download the Arabic GLiNER Model](#download-the-arabic-gliner-model)
- [Run the Backend](#run-the-backend)
- [Run the Web Demo](#run-the-web-demo)
- [Load the Browser Extension](#load-the-browser-extension)
- [Use LeakLens with ChatGPT](#use-leaklens-with-chatgpt)
- [Example Inputs](#example-inputs)
- [Evaluation](#evaluation)
- [Notes](#notes)
- [License](#license)

---

# Overview

LeakLens is a browser-integrated privacy layer built during an AI hackathon.

The goal is simple: users often paste real messages, credentials, or customer data into AI tools. LeakLens helps detect that sensitive information locally before it leaves the user’s machine.

Features:

* Arabic and English sensitive data detection
* Regex-based PII detection
* Secret scanning for passwords, API keys, and database URLs
* Arabic NER support using GLiNER
* English NER support using spaCy
* Web demo interface
* Browser extension for ChatGPT usage
* Local-first design

---

# Project Structure

```text
LeakLens/
│
├── backend/
│   ├── api/
│   │   └── main.py
│   │
│   ├── scanner/
│   │   ├── arabic_ner.py
│   │   ├── detector.py
│   │   ├── secret_scanner.py
│   │   └── spacy_ner.py
│   │
│   └── tests/
│       └── test_scanner.py
│
├── demo-web/
│   ├── index.html
│   ├── app.js
│   ├── style.css
│   └── README.md
│
├── extension/
│   ├── manifest.json
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   ├── popup.css
│   └── icons/
│
├── tools/
│   ├── demo_test_bank.json
│   ├── evaluation/
│   ├── payloads/
│   └── scripts/
│
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
````

---

# Requirements

Before running the project, ensure you have:

* Windows
* Python 3.11
* Git
* Chrome or Edge browser

Check your Python version:

```powershell
py -3.11 --version
```

Expected:

```text
Python 3.11.x
```

If Python 3.11 is not installed, install it from:

```text
https://www.python.org/downloads/release/python-311/
```

---

# Obtain the Project

Clone the repository:

```powershell
git clone https://github.com/QuantumDevPro/LeakLens.git
cd LeakLens
```

---

# Install Dependencies

Before installing dependencies, create and activate a virtual environment.

## 1. Create a virtual environment

From the project root directory:

```powershell
py -3.11 -m venv .venv
```

## 2. Activate the virtual environment

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate
```

On Git Bash:

```bash
source .venv/Scripts/activate
```

After activation, your terminal prompt should show `(.venv)`.

## 3. Upgrade pip

```powershell
python -m pip install --upgrade pip
```

## 4. Install project dependencies

```powershell
pip install -r requirements.txt
```

---

# Download the Arabic GLiNER Model

The Arabic GLiNER model is required for Arabic NER detection.

The model is **not included in the repository** because of its size.

From the project root directory, run:

```powershell
git clone https://huggingface.co/NAMAA-Space/gliner_arabic-v2.1 models/gliner_arabic
```

After cloning, the folder should look like:

```text
models/
└── gliner_arabic/
```

---

# Run the Backend

From the project root directory:

```powershell
python -m uvicorn backend.api.main:app --reload
```

Expected local API:

```text
http://127.0.0.1:8000
```

Keep this terminal open while using the demo or extension.

---

# Run the Web Demo

Open a second terminal.

Go to the web demo folder:

```powershell
cd demo-web
```

Start a local web server using Python 3.11:

```powershell
py -3.11 -m http.server 5500
```

Open the demo page:

```text
http://127.0.0.1:5500
```

---

# Load the Browser Extension

1. Open Chrome or Edge.
2. Go to:

```text
chrome://extensions/
```

3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the `extension/` folder from the LeakLens project.

The extension should now appear in your browser.

---

# Use LeakLens with ChatGPT

1. Make sure the backend server is running.
2. Make sure the web demo server is running if needed.
3. Make sure the browser extension is enabled.
4. Open:

```text
https://chatgpt.com/
```

5. Paste a prompt containing test sensitive data.
6. LeakLens will scan the text and apply the selected policy:

* `warn`
* `redact`
* `block`

---

# Example Inputs

## Arabic Example

```text
مرحبًا، أنا سارة العبدالله. رقمي +966501234567 وبريدي sara.alabdullah@example.com. استخدمت مؤقتًا api_key = "abc1234567890SECRETKEY" وقاعدة البيانات DATABASE_URL=postgresql://appuser:dbpass123@localhost:5432/leaklens_db
```

## English Example

```text
My name is Sarah Johnson. Email: sarah@example.com. Phone: +966501234567. Temporary password: TempPass2026##
```

## Payment Example

```text
Customer payment: card 4111111111111111, email billing@example.com, phone +966501112233.
```

---

# Evaluation

LeakLens includes a curated test bank:

```text
tools/demo_test_bank.json
```

To run the evaluation:

```powershell
python -m tools.scripts.run_demo_test_bank
```

The evaluation covers:

* Names
* Emails
* Phone numbers
* IDs
* Credit cards
* Passwords
* API keys
* Database credentials
* Safe prompts for false-positive testing

---

# Notes

* LeakLens is local-first. Sensitive text is scanned locally.
* The Arabic GLiNER model must be downloaded manually.
* The `models/` directory is ignored by Git and should not be committed.
* Python 3.11 is recommended and used in the setup commands.
* This project was built as part of an AI hackathon demo and can be extended with more detection rules.

---

# License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
