"""
PII Guardian — Limited spaCy NER Layer

Purpose:
- Use local spaCy only as a conservative English PERSON detector.
- Structured PII stays with regex.
- Arabic semantic PII stays with NAMAA / GLiNER.
- Runs fully offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import spacy


ALLOWED_LABELS = {
    "PERSON": ("person_name", "low", 0.82),
}

BAD_ENTITY_CHARS = re.compile(r"[@+\d:/\\]|https?://|www\.", re.IGNORECASE)
ARABIC_CHARS = re.compile(r"[\u0600-\u06FF]")
LATIN_NAME = re.compile(r"^[A-Za-z][A-Za-z'.-]*(?:\s+[A-Za-z][A-Za-z'.-]*){1,3}$")


@dataclass
class SpacyDetection:
    pii_type: str
    value: str
    severity: str
    confidence: float
    explanation: str
    source: str = "spacy"

    @property
    def redacted(self) -> str:
        if self.pii_type == "person_name":
            return self._mask_name(self.value)
        return "[REDACTED]"

    @staticmethod
    def _mask_name(value: str) -> str:
        words = value.split()
        return " ".join(
            word[0] + "*" * (len(word) - 1)
            if len(word) > 1
            else "*"
            for word in words
        )


try:
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except OSError:
    SPACY_AVAILABLE = False
    print("⚠️ spaCy model not found. Run: python -m spacy download en_core_web_sm")


def _looks_like_safe_english_name(value: str) -> bool:
    value = value.strip()

    if len(value) < 3:
        return False

    if ARABIC_CHARS.search(value):
        return False

    if BAD_ENTITY_CHARS.search(value):
        return False

    if not LATIN_NAME.fullmatch(value):
        return False

    return True


def spacy_scan(text: str, already_found_types: list[str] | None = None) -> list[SpacyDetection]:
    """
    Conservative spaCy layer.

    Only returns English PERSON entities that look like real names.
    Does not detect structured PII.
    Does not process Arabic entities.
    """
    if not SPACY_AVAILABLE:
        return []

    already = set(already_found_types or [])

    if "person_name" in already:
        return []

    doc = nlp(text)
    detections: list[SpacyDetection] = []

    for ent in doc.ents:
        mapping = ALLOWED_LABELS.get(ent.label_)
        if not mapping:
            continue

        value = ent.text.strip()

        if not _looks_like_safe_english_name(value):
            continue

        pii_type, severity, confidence = mapping

        detections.append(
            SpacyDetection(
                pii_type=pii_type,
                value=value,
                severity=severity,
                confidence=confidence,
                explanation="Detected English person name using local spaCy NER",
            )
        )

    return detections