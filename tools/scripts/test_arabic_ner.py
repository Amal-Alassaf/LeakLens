from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.scanner.arabic_ner import scan_arabic_ner


TEST_CASES = [
    {
        "name": "Arabic person + city + date",
        "text": "قابلت نورة العتيبي في الرياض يوم الأحد.",
    },
    {
        "name": "Organization + location",
        "text": "يعمل أحمد محمد في شركة أرامكو في الظهران.",
    },
    {
        "name": "Structured PII should mostly be ignored by NER",
        "text": "البريد الإلكتروني test@example.com ورقم الجوال +966501234567.",
    },
    {
        "name": "Bank/card style text should stay regex responsibility",
        "text": "رقم البطاقة 4111 1111 1111 1111 ورقم الحساب SA0380000000608010167519.",
    },
    {
        "name": "No PII / general sentence",
        "text": "هذا اختبار بسيط للنظام ولا يحتوي على بيانات شخصية واضحة.",
    },
    {
        "name": "Arabic date phrase",
        "text": "تاريخ الموعد هو 15 يناير 2025 في جدة.",
    },
    {
        "name": "Possible false positive title",
        "text": "زار المدير العام المكتب الرئيسي صباح اليوم.",
    },
]


def run_threshold(threshold: float) -> None:
    print("=" * 80)
    print(f"Threshold: {threshold}")
    print("=" * 80)

    for case in TEST_CASES:
        print()
        print(f"Case: {case['name']}")
        print(f"Text: {case['text']}")

        detections = scan_arabic_ner(case["text"], threshold=threshold)

        if not detections:
            print("Detections: none")
            continue

        print("Detections:")
        for detection in detections:
            print(
                f"  - {detection['pii_type']} | "
                f"{detection['value']} | "
                f"confidence={detection['confidence']} | "
                f"start={detection['start']} | "
                f"end={detection['end']}"
            )


def main() -> None:
    for threshold in [0.50, 0.60, 0.70, 0.80]:
        run_threshold(threshold)


if __name__ == "__main__":
    main()