from backend.scanner.detector import PIIScanner


def main() -> None:
    scanner = PIIScanner()

    tests = [
        "My password is Pa$$w0rd##",
        "my password Pa$$w0rd##",
        "password was Pa$$w0rd##",
        "password: Pa$$w0rd##",
        "password=Pa$$w0rd##",
        "pass: Pa$$w0rd##",
        "my pass = Pa$$w0rd##",
        "pwd=\"Pa$$w0rd##\"",
        "passwd='Pa$$w0rd##'",
        "passphrase `Pa$$w0rd##`",
        "كلمة السر: Pa$$w0rd##",
        "كلمة المرور = Pa$$w0rd##",
        "الباسورد: Pa$$w0rd##",
        "باسورد = Pa$$w0rd##",
        "الباس Pa$$w0rd##",
        "This sentence has no password.",
    ]

    for text in tests:
        result = scanner.scan(text)
        print("\nTEXT:", text)
        print("DETECTIONS:", result.detections)
        print("REDACTED:", result.redacted_text)


if __name__ == "__main__":
    main()