"""
PII Guardian — REST API
Run with:  uvicorn backend.api.main:app --reload
Then open: http://127.0.0.1:8000/docs
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Literal

from backend.scanner.detector import PIIScanner, Severity
from backend.scanner.spacy_ner import spacy_scan, SPACY_AVAILABLE

app = FastAPI(
    title="PII Guardian API",
    description="Scans text for PII before it reaches an AI model.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = PIIScanner()


class ScanRequest(BaseModel):
    text: str
    policy: Literal["block", "redact", "warn"] = "warn"


class DetectionOut(BaseModel):
    pii_type: str
    value: str
    redacted: str
    severity: str
    confidence: float
    explanation: str


class ScanResponse(BaseModel):
    is_safe: bool
    action_taken: str
    risk_score: float
    detections: list[DetectionOut]
    original_text: str
    output_text: str
    summary: str


@app.get("/")
def root():
    return {"service": "PII Guardian", "status": "running", "version": "0.1.0"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan_text(req: ScanRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
    if len(req.text) > 10_000:
        raise HTTPException(status_code=400, detail="Text too long (max 10,000 characters).")

    result = scanner.scan(req.text)

    detections_out = [
        DetectionOut(
            pii_type=d.pii_type.value,
            value=d.value,
            redacted=d.redacted,
            severity=d.severity.value,
            confidence=round(d.confidence, 2),
            explanation=d.explanation,
        )
        for d in result.detections
    ]
    # --- Layer 2: spaCy NER ---
    already_found = [d.pii_type.value for d in result.detections]
    spacy_detections = spacy_scan(req.text, already_found)

    for d in spacy_detections:
            detections_out.append(DetectionOut(
            pii_type=d.pii_type,
            value=d.value,
            redacted=d.redacted,
            severity=d.severity,
            confidence=round(d.confidence, 2),
            explanation=d.explanation,
            source="spacy",
            ))

    if spacy_detections:
        result.is_safe = False

    if result.is_safe:
        action_taken = "allowed"
        output_text = req.text
    elif req.policy == "block":
        action_taken = "blocked"
        output_text = ""
    elif req.policy == "redact":
        action_taken = "redacted"
        output_text = result.redacted_text
    else:
        action_taken = "allowed_with_warning"
        output_text = req.text

    return ScanResponse(
        is_safe=result.is_safe,
        action_taken=action_taken,
        risk_score=result.risk_score,
        detections=detections_out,
        original_text=req.text,
        output_text=output_text,
        summary=result.summary,
    )

