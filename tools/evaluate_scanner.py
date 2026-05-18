import json
from collections import defaultdict
from pathlib import Path

from backend.scanner.detector import PIIScanner, PIIType


DATASET_PATH = Path("tools/eval_dataset.json")


def normalize_type(pii_type):
    if hasattr(pii_type, "value"):
        return pii_type.value
    return str(pii_type)


def detection_key(item: dict) -> tuple[str, str]:
    return item["pii_type"], item["value"]


def main() -> None:
    scanner = PIIScanner()

    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))

    total_tp = 0
    total_fp = 0
    total_fn = 0

    by_type = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for case in dataset:
        result = scanner.scan(case["text"])

        expected = {
            detection_key(item)
            for item in case["expected"]
        }

        predicted = {
            (
                normalize_type(d.pii_type),
                d.value,
            )
            for d in result.detections
        }

        tp_items = predicted & expected
        fp_items = predicted - expected
        fn_items = expected - predicted

        total_tp += len(tp_items)
        total_fp += len(fp_items)
        total_fn += len(fn_items)

        for pii_type, _ in tp_items:
            by_type[pii_type]["tp"] += 1

        for pii_type, _ in fp_items:
            by_type[pii_type]["fp"] += 1

        for pii_type, _ in fn_items:
            by_type[pii_type]["fn"] += 1

        print("\n" + "=" * 80)
        print(f"CASE: {case['id']}")
        print(f"TEXT: {case['text']}")
        print(f"EXPECTED: {sorted(expected)}")
        print(f"PREDICTED: {sorted(predicted)}")
        print(f"TP: {sorted(tp_items)}")
        print(f"FP: {sorted(fp_items)}")
        print(f"FN: {sorted(fn_items)}")

    precision = total_tp / (total_tp + total_fp) if total_tp + total_fp else 0.0
    recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    print("\n" + "=" * 80)
    print("OVERALL METRICS")
    print("=" * 80)
    print(f"True positives:  {total_tp}")
    print(f"False positives: {total_fp}")
    print(f"False negatives: {total_fn}")
    print(f"Precision:       {precision:.3f}")
    print(f"Recall:          {recall:.3f}")
    print(f"F1 score:        {f1:.3f}")

    print("\n" + "=" * 80)
    print("METRICS BY TYPE")
    print("=" * 80)

    for pii_type, counts in sorted(by_type.items()):
        tp = counts["tp"]
        fp = counts["fp"]
        fn = counts["fn"]

        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0

        print(
            f"{pii_type:20s} "
            f"TP={tp:<3d} FP={fp:<3d} FN={fn:<3d} "
            f"P={p:.3f} R={r:.3f} F1={f:.3f}"
        )


if __name__ == "__main__":
    main()