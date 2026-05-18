from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from gliner import GLiNER


MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "gliner_arabic"

ARABIC_NER_LABELS = ["person", "location", "organization", "date"]

PII_TYPE_MAP = {
    "person": "person_name",
    "location": "location",
    "organization": "organization",
    "date": "date",
}

ARABIC_GENERIC_PERSON_PHRASES = {
    "المدير العام",
    "الرئيس المصري",
    "الرئيس التنفيذي",
    "المدير التنفيذي",
    "الموظف",
    "الموظفة",
    "العميل",
    "العميلة",
    "المستخدم",
    "المستخدمة",
}

ARABIC_GENERIC_LOCATION_PHRASES = {
    "المكتب الرئيسي",
    "المكتب",
    "الفرع",
    "المقر",
    "الشركة",
}

ARABIC_RELATIVE_DATES = {
    "اليوم",
    "غدا",
    "غداً",
    "أمس",
    "صباح اليوم",
    "مساء اليوم",
}

@lru_cache(maxsize=1)
def get_arabic_ner_model() -> GLiNER:
    return GLiNER.from_pretrained(str(MODEL_PATH))


def redact_arabic_entity(value: str) -> str:
    if len(value) <= 2:
        return "*" * len(value)

    return value[0] + ("*" * (len(value) - 2)) + value[-1]

def should_keep_arabic_entity(label: str, value: str) -> bool:
    normalized = " ".join(value.strip().split())

    if not normalized:
        return False

    if label == "person" and normalized in ARABIC_GENERIC_PERSON_PHRASES:
        return False

    if label == "location" and normalized in ARABIC_GENERIC_LOCATION_PHRASES:
        return False

    if label == "date" and normalized in ARABIC_RELATIVE_DATES:
        return False

    return True

    
def scan_arabic_ner(text: str, threshold: float = 0.80) -> list[dict[str, Any]]:
    if not text or not text.strip():
        return []

    model = get_arabic_ner_model()

    entities = model.predict_entities(
        text,
        ARABIC_NER_LABELS,
        threshold=threshold,
    )

    results: list[dict[str, Any]] = []

    for entity in entities:
        label = entity["label"]
        value = entity["text"]

        if not should_keep_arabic_entity(label, value):
            continue

        results.append(
            {
                "pii_type": PII_TYPE_MAP.get(label, label),
                "value": value,
                "redacted": redact_arabic_entity(value),
                "severity": "medium",
                "start": entity["start"],
                "end": entity["end"],
                "confidence": round(float(entity["score"]), 4),
                "explanation": f"Detected Arabic {label} using local GLiNER NER model",
                "source": "arabic_ner",
            }
        )

    return results


def main() -> None:
    text = "زار الرئيس المصري عبد الفتاح السيسي القاهرة يوم الاثنين."
    detections = scan_arabic_ner(text)

    print("Text:", text)
    print("Detections:")
    for detection in detections:
        print(detection)


if __name__ == "__main__":
    main()