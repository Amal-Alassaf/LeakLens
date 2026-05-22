from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.scanner.detector import PIIScanner


def main() -> None:
    scanner = PIIScanner()

    texts = [
        "قابلت نورة العتيبي في الرياض يوم الأحد.",
        "يعمل أحمد محمد في شركة أرامكو في الظهران.",
        "البريد الإلكتروني test@example.com ورقم الجوال +966501234567.",
        "اسمي سارة العبدالله ورقمي +966501234567 وأعيش في جدة.",
        "رقم البطاقة 4111111111111111 وتاريخ الموعد هو 15 يناير 2025 في جدة.",
        "هذا اختبار بسيط للنظام ولا يحتوي على بيانات شخصية واضحة.",
    ]

    for index, text in enumerate(texts, start=1):
        print("=" * 80)
        print(f"Case {index}")
        print("Original:")
        print(text)

        result = scanner.scan(text)

        print()
        print(f"Is safe: {result.is_safe}")
        print(f"Risk score: {result.risk_score}")
        print("Redacted:")
        print(result.redacted_text)

        print("Detections:")
        if not result.detections:
            print("  none")
            continue

        for detection in result.detections:
            print(
                f"  - {detection.pii_type.value} | "
                f"{detection.value} -> {detection.redacted} | "
                f"severity={detection.severity.value} | "
                f"confidence={round(detection.confidence, 4)} | "
                f"source={detection.source} | "
                f"span=({detection.start}, {detection.end})"
            )


if __name__ == "__main__":
    main()