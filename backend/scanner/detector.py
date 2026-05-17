"""
PII Guardian — Core Detection Engine
Detects personally identifiable information using regex patterns
and rule-based heuristics. Designed to be fast and explainable.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class PIIType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    NATIONAL_ID = "national_id"
    CREDIT_CARD = "credit_card"
    PASSWORD = "password"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    PERSON_NAME = "person_name"
    BANK_ACCOUNT = "bank_account"
    PASSPORT = "passport"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Detection:
    pii_type: PIIType
    value: str
    redacted: str
    severity: Severity
    start: int
    end: int
    confidence: float
    explanation: str = ""


@dataclass
class ScanResult:
    original_text: str
    is_safe: bool
    detections: list[Detection] = field(default_factory=list)
    redacted_text: str = ""
    risk_score: float = 0.0

    @property
    def high_severity_count(self) -> int:
        return sum(1 for d in self.detections if d.severity == Severity.HIGH)

    @property
    def summary(self) -> str:
        if not self.detections:
            return "No PII detected."
        types = [d.pii_type.value.replace("_", " ") for d in self.detections]
        return f"Detected: {', '.join(set(types))}"
        
@dataclass
class Detection:
    pii_type: PIIType
    value: str
    redacted: str
    severity: Severity
    start: int
    end: int
    confidence: float
    explanation: str = ""
    source: str = "regex"

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PATTERNS: list[dict] = [
    {
        "type": PIIType.EMAIL,
        "severity": Severity.MEDIUM,
        "confidence": 0.97,
        "pattern": re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        "explanation": "Email address found",
    },
    {
        "type": PIIType.PHONE,
        "severity": Severity.MEDIUM,
        "confidence": 0.88,
        "pattern": re.compile(
            r"(?<!\d)"
            r"(\+?966[-\s]?|0)"
            r"[5][0-9]{8}"
            r"(?!\d)"
        ),
        "explanation": "Saudi phone number found",
    },
    {
        "type": PIIType.PHONE,
        "severity": Severity.MEDIUM,
        "confidence": 0.80,
        "pattern": re.compile(
            r"(?<!\d)"
            r"(\+?[1-9]\d{0,2}[-.\s]?)?"
            r"\(?\d{3}\)?[-.\s]"           # separator required after area code
            r"\d{3}[-.\s]?"
            r"\d{4}"
            r"(?!\d)"
        ),
        "explanation": "Phone number found",
    },
    {
        "type": PIIType.NATIONAL_ID,
        "severity": Severity.HIGH,
        "confidence": 0.93,
        "pattern": re.compile(
            r"(?<!\d)"
            r"[12]\d{9}"
            r"(?!\d)"
        ),
        "explanation": "Saudi National ID or Iqama number found",
    },
    {
        "type": PIIType.CREDIT_CARD,
        "severity": Severity.HIGH,
        "confidence": 0.95,
        "pattern": re.compile(
            r"(?<!\d)"
            r"(?:"
            r"4[0-9]{12}(?:[0-9]{3})?"
            r"|5[1-5][0-9]{14}"
            r"|3[47][0-9]{13}"
            r"|6(?:011|5[0-9]{2})[0-9]{12}"
            r")"
            r"(?!\d)"
        ),
        "explanation": "Credit card number found",
    },
    {
        "type": PIIType.PASSWORD,
        "severity": Severity.HIGH,
        "confidence": 0.90,
        "pattern": re.compile(
            r"(?i)"
            r"\b("
            r"login\s+password|password|passwd|pwd|pass|credential|credentials|"
            r"كلمة\s*السر|كلمة\s*المرور"
            r")\b"
            r"\s*"
            r"(?:is|:|=)"
            r"\s*"
            r"(\S+)"
        ),
        "explanation": "Password or credential found",
    },
    {
        "type": PIIType.IP_ADDRESS,
        "severity": Severity.MEDIUM,
        "confidence": 0.99,
        "pattern": re.compile(
            r"\b"
            r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            r"\b"
        ),
        "explanation": "IP address found",
    },
    {
        "type": PIIType.PASSPORT,
        "severity": Severity.HIGH,
        "confidence": 0.82,
        "pattern": re.compile(
            r"(?i)(?:passport|جواز\s*السفر)[^\d]*([A-Z]{1,2}\d{6,9})",
            re.IGNORECASE
        ),
        "explanation": "Passport number found",
    },
    {
        "type": PIIType.DATE_OF_BIRTH,
        "severity": Severity.LOW,
        "confidence": 0.75,
        "pattern": re.compile(
            r"(?i)(?:dob|date\s+of\s+birth|born|تاريخ\s*الميلاد)[^\d]*"
            r"(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4})"
        ),
        "explanation": "Date of birth found",
    },
]

NAME_PREFIXES = [
    "اسمي", "أنا", "أحمد", "محمد", "عبدالله", "خالد", "سعد", "فيصل",
    "نورة", "منى", "ريم", "سارة", "لطيفة",
    "my name is", "i am", "i'm", "this is", "call me",
    "mr.", "mrs.", "ms.", "dr.", "prof.",
]

NAME_PATTERN = re.compile(
    r"(?i)(?:" + "|".join(re.escape(p) for p in NAME_PREFIXES) + r")"
    r"\s+"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}(?=\s*[,.\?!؟،\n]|\s+(?:and|or|but|I |my |the )|$))"
    r"|(?:" + "|".join(re.escape(p) for p in NAME_PREFIXES) + r")"
    r"\s+([\u0600-\u06FF]{3,}(?:\s+[\u0600-\u06FF]{3,}){1,3})"
)


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


class PIIScanner:
    def __init__(self, min_confidence: float = 0.70):
        self.min_confidence = min_confidence

    def scan(self, text: str) -> ScanResult:
        detections: list[Detection] = []
        seen_spans: list[tuple[int, int]] = []

        for spec in PATTERNS:
            for match in spec["pattern"].finditer(text):
                start, end = match.start(), match.end()
                value = match.group()

                if spec["type"] == PIIType.PASSWORD and match.lastindex and match.group(2):
                    start, end = match.start(2), match.end(2)
                    value = match.group(2)

                if any(s <= start < e or s < end <= e for s, e in seen_spans):
                    continue

                confidence = spec["confidence"]

                if spec["type"] == PIIType.CREDIT_CARD:
                    digits_only = re.sub(r"\D", "", value)
                    if not _luhn_check(digits_only):
                        confidence *= 0.4

                if confidence < self.min_confidence:
                    continue

                detection = Detection(
                    pii_type=spec["type"],
                    value=value,
                    redacted="",
                    severity=spec["severity"],
                    start=start,
                    end=end,
                    confidence=confidence,
                    explanation=spec["explanation"],
                )

                detection.redacted = self._mask_detection(detection)
                detections.append(detection)
                seen_spans.append((start, end))

            for match in NAME_PATTERN.finditer(text):
                start, end = match.start(), match.end()

                if any(s <= start < e or s < end <= e for s, e in seen_spans):
                    continue

                name_value = match.group(1) if match.lastindex else match.group()

                detection = Detection(
                    pii_type=PIIType.PERSON_NAME,
                    value=name_value,
                    redacted="",
                    severity=Severity.LOW,
                    start=match.start(1) if match.lastindex else start,
                    end=match.end(1) if match.lastindex else end,
                    confidence=0.78,
                    explanation="Person name found near identifying keyword",
                )

                detection.redacted = self._mask_detection(detection)
                detections.append(detection)
                seen_spans.append((start, end))

        detections.sort(key=lambda d: d.start)
        redacted = self._redact(text, detections)

        severity_weights = {Severity.HIGH: 1.0, Severity.MEDIUM: 0.5, Severity.LOW: 0.2}
        raw_score = sum(severity_weights[d.severity] * d.confidence for d in detections)
        risk_score = min(1.0, raw_score / max(1, len(text) / 200))

        return ScanResult(
            original_text=text,
            is_safe=len(detections) == 0,
            detections=detections,
            redacted_text=redacted,
            risk_score=round(risk_score, 3),
        )

    def _redact(self, text: str, detections: list[Detection]) -> str:
        if not detections:
            return text

        result = []
        cursor = 0

        for d in detections:
            result.append(text[cursor:d.start])
            result.append(d.redacted)
            cursor = d.end

        result.append(text[cursor:])
        return "".join(result)

    def _mask_detection(self, d: Detection) -> str:
        value = d.value

        if d.pii_type == PIIType.EMAIL:
            name, domain = value.split("@", 1)
            return name[:2] + "***@" + domain

        if d.pii_type == PIIType.PHONE:
            return value[:5] + "******" + value[-2:]

        if d.pii_type == PIIType.NATIONAL_ID:
            return value[:3] + "****" + value[-3:]

        if d.pii_type == PIIType.PASSWORD:
            return "[PASSWORD REDACTED]"

        if d.pii_type == PIIType.CREDIT_CARD:
            return "**** **** **** " + value[-4:]

        if d.pii_type == PIIType.IP_ADDRESS:
            parts = value.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.*.*"
            return "[IP REDACTED]"

        if d.pii_type == PIIType.PERSON_NAME:
            words = value.split()
            return " ".join(
                word[0] + "*" * (len(word) - 1)
                if len(word) > 1 else "*"
                for word in words
            )

        if d.pii_type == PIIType.PASSPORT:
            if len(value) <= 4:
                return "[PASSPORT REDACTED]"
            return value[:3] + "*" * max(3, len(value) - 6) + value[-3:]

        if d.pii_type == PIIType.DATE_OF_BIRTH:
            # Hide day, month, and year completely
            if "/" in value:
                return "**/**/****"
            if "-" in value:
                return "**-**-****"
            if "." in value:
                return "**.**.****"
            return "[DOB REDACTED]"

        return d.redacted
