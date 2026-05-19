import json
from pathlib import Path

from backend.scanner.detector import PIIScanner


DATASET_PATH = Path("tools/demo_test_bank.json")


def pii_type_value(pii_type):
    return pii_type.value if hasattr(pii_type, "value") else str(pii_type)


def main() -> None:
    scanner = PIIScanner()
    cases = json.loads(DATASET_PATH.read_text(encoding="utf-8"))

    for case in cases:
        result = scanner.scan(case["text"])

        predicted_types = [pii_type_value(d.pii_type) for d in result.detections]
        expected_types = case["expected_types"]

        extra = sorted(set(predicted_types) - set(expected_types))
        missed = sorted(set(expected_types) - set(predicted_types))

        print("\n" + "=" * 90)
        print(f"CASE: {case['id']}")
        print(f"EXPECTED TYPES: {expected_types}")
        print(f"PREDICTED TYPES: {predicted_types}")
        print(f"EXTRA TYPES: {extra}")
        print(f"MISSED TYPES: {missed}")
        print(f"REDACTED: {result.redacted_text}")

        if result.detections:
            print("DETECTIONS:")
            for d in result.detections:
                print(
                    {
                        "pii_type": pii_type_value(d.pii_type),
                        "value": d.value,
                        "source": d.source,
                        "confidence": round(d.confidence, 2),
                    }
                )


if __name__ == "__main__":
    main()
