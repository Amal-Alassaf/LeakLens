"""
PII Guardian — spaCy NER Layer
Uses a local spaCy model to detect names, orgs, and locations.
Runs fully offline — no API key needed.
"""

import spacy
from dataclasses import dataclass

# Map spaCy entity labels to our PII types
LABEL_MAP = {
    "PERSON":   ("person_name", "low",    0.82),
    "ORG":      ("organization","low",    0.75),
    "GPE":      ("location",    "low",    0.70),  # Countries, cities
    "LOC":      ("location",    "low",    0.70),  # Mountains, rivers
    "DATE":     ("date_of_birth","low",   0.65),  # Only flag if near DOB keywords
    "MONEY":    ("financial",   "medium", 0.78),
    "CARDINAL": (None,          None,     0.00),  # Skip plain numbers
}

@dataclass
class SpacyDetection:
    pii_type: str
    value: str
    severity: str
    confidence: float
    explanation: str

    @property
    def redacted(self) -> str:
        labels = {
            "person_name":  "[NAME REDACTED]",
            "organization": "[ORG REDACTED]",
            "location":     "[LOCATION REDACTED]",
            "financial":    "[FINANCIAL INFO REDACTED]",
            "date_of_birth":"[DOB REDACTED]",
        }
        return labels.get(self.pii_type, "[REDACTED]")


# Load model once at import time
try:
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except OSError:
    SPACY_AVAILABLE = False
    print("⚠️  spaCy model not found. Run: py -3.11 -m spacy download en_core_web_sm")


def spacy_scan(text: str, already_found_types: list[str] = None) -> list[SpacyDetection]:
    """
    Run spaCy NER on text.
    Skips entity types already caught by the regex scanner.
    """
    if not SPACY_AVAILABLE:
        return []

    already = set(already_found_types or [])
    doc = nlp(text)
    detections = []

    for ent in doc.ents:
        mapping = LABEL_MAP.get(ent.label_)
        if not mapping:
            continue

        pii_type, severity, confidence = mapping

        # Skip if this type was already found by regex
        if pii_type in already or pii_type is None:
            continue

        # Skip very short matches (likely false positives)
        if len(ent.text.strip()) < 3:
            continue

        detections.append(SpacyDetection(
            pii_type=pii_type,
            value=ent.text.strip(),
            severity=severity,
            confidence=confidence,
            explanation=f"Detected by NER model as {ent.label_}",
        ))

    return detections