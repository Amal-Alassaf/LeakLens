"""
PII Guardian — Test Suite
Run from the pii-guardian/ root folder with:
    python -m backend.tests.test_scanner
"""

from backend.scanner.detector import PIIScanner, Severity

scanner = PIIScanner()

TEST_CASES = [
    {
        "label": "Clean message",
        "text": "Can you help me write a Python function to sort a list?",
        "expect_safe": True,
    },
    {
        "label": "Email address",
        "text": "Please send the report to ahmed.ali@company.com by tomorrow.",
        "expect_safe": False,
    },
    {
        "label": "Saudi phone number",
        "text": "Call me on 0501234567 or +966501234567 anytime.",
        "expect_safe": False,
    },
    {
        "label": "Saudi National ID",
        "text": "My national ID is 1098765432, please verify it.",
        "expect_safe": False,
    },
    {
        "label": "Credit card",
        "text": "Charge my card 4532015112830366 for the subscription.",
        "expect_safe": False,
    },
    {
        "label": "Password leak",
        "text": "My password is SuperSecret123! — can you check if it's strong?",
        "expect_safe": False,
    },
    {
        "label": "IP address",
        "text": "The server is running at 192.168.1.105 on port 8080.",
        "expect_safe": False,
    },
    {
        "label": "Person name (English)",
        "text": "My name is Ahmed Abdullah and I need help with my account.",
        "expect_safe": False,
    },
    {
        "label": "Multiple PII types",
        "text": "Hi, I'm Sara Hassan. Email me at sara@example.com or call 0551234567. My ID is 2034567891.",
        "expect_safe": False,
    },
    {
        "label": "Arabic password",
        "text": "كلمة المرور: admin2024 هل يمكنك مساعدتي؟",
        "expect_safe": False,
    },
]

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"

print("\n" + "="*60)
print("  PII Guardian — Scanner Test Suite")
print("="*60)

passed = 0
for tc in TEST_CASES:
    result = scanner.scan(tc["text"])
    ok = result.is_safe == tc["expect_safe"]
    passed += ok
    status = PASS if ok else FAIL

    print(f"\n{status} {tc['label']}")
    print(f"   Input   : {tc['text'][:65]}{'...' if len(tc['text']) > 65 else ''}")

    if result.detections:
        for d in result.detections:
            sev_color = "\033[91m" if d.severity == Severity.HIGH else "\033[93m" if d.severity == Severity.MEDIUM else "\033[94m"
            print(f"   {sev_color}[{d.severity.value.upper()}]\033[0m {d.pii_type.value}: '{d.value}' (confidence: {d.confidence:.0%})")
        print(f"   Redacted: {result.redacted_text[:65]}{'...' if len(result.redacted_text) > 65 else ''}")
        print(f"   Risk score: {result.risk_score}")
    else:
        print(f"   No PII detected ✓")

print("\n" + "="*60)
print(f"  Results: {passed}/{len(TEST_CASES)} tests passed")
print("="*60 + "\n")
