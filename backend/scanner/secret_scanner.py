"""
Local secret scanner for LeakLens.

This module detects common API keys, tokens, and private keys without
sending text to any external service.
"""

from __future__ import annotations

import re
from typing import Any


SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "pii_type": "openai_api_key",
        "pattern": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        "severity": "high",
        "confidence": 0.95,
        "explanation": "Possible OpenAI API key detected.",
    },
    {
        "pii_type": "github_token",
        "pattern": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        "severity": "high",
        "confidence": 0.95,
        "explanation": "Possible GitHub token detected.",
    },
    {
        "pii_type": "aws_access_key_id",
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "severity": "high",
        "confidence": 0.95,
        "explanation": "Possible AWS access key ID detected.",
    },
    {
        "pii_type": "jwt_token",
        "pattern": re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        "severity": "high",
        "confidence": 0.90,
        "explanation": "Possible JWT token detected.",
    },
    {
        "pii_type": "bearer_token",
        "pattern": re.compile(
            r"\bBearer\s+([A-Za-z0-9._~+/=-]{20,})\b",
            re.IGNORECASE,
        ),
        "severity": "high",
        "confidence": 0.90,
        "explanation": "Possible bearer token detected.",
    },
    {
        "pii_type": "private_key",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": "critical",
        "confidence": 0.98,
        "explanation": "Possible private key block detected.",
    },
    {
        "pii_type": "access_token",
        "pattern": re.compile(
            r"\b(?:access_token|accessToken)\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{20,})[\"']?",
            re.IGNORECASE,
        ),
        "severity": "high",
        "confidence": 0.85,
        "explanation": "Possible access token detected.",
    },
    {
        "pii_type": "api_key",
        "pattern": re.compile(
            r"\b(?:api_key|apikey|api-key|x-api-key)\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{16,})[\"']?",
            re.IGNORECASE,
        ),
        "severity": "high",
        "confidence": 0.85,
        "explanation": "Possible API key detected.",
    },
    {
        "pii_type": "secret_key",
        "pattern": re.compile(
            r"\b(?:secret_key|secretKey|secret-key|client_secret)\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{16,})[\"']?",
            re.IGNORECASE,
        ),
        "severity": "high",
        "confidence": 0.85,
        "explanation": "Possible secret key detected.",
    },    {
        "pii_type": "database_url",
        "pattern": re.compile(
            r"\b(?:DATABASE_URL|DB_URL|DATABASE_URI|DB_URI)\s*[:=]\s*[\"']?"
            r"((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s\"']+)"
            r"[\"']?",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "confidence": 0.95,
        "explanation": "Possible database connection URL detected.",
    },
    {
        "pii_type": "postgres_uri",
        "pattern": re.compile(
            r"\b(postgres(?:ql)?://[^\s\"']+)",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "confidence": 0.95,
        "explanation": "Possible PostgreSQL connection URI detected.",
    },
    {
        "pii_type": "mysql_uri",
        "pattern": re.compile(
            r"\b(mysql|mariadb)://[^\s\"']+",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "confidence": 0.95,
        "explanation": "Possible MySQL/MariaDB connection URI detected.",
    },
    {
        "pii_type": "mongodb_uri",
        "pattern": re.compile(
            r"\b(mongodb(?:\+srv)?://[^\s\"']+)",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "confidence": 0.95,
        "explanation": "Possible MongoDB connection URI detected.",
    },
    {
        "pii_type": "redis_uri",
        "pattern": re.compile(
            r"\b(redis://[^\s\"']+)",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "confidence": 0.95,
        "explanation": "Possible Redis connection URI detected.",
    },
    {
        "pii_type": "database_password",
        "pattern": re.compile(
            r"\b(?:DB_PASSWORD|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD|MONGO_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*[\"']?"
            r"([^\s\"']{8,})"
            r"[\"']?",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "confidence": 0.90,
        "explanation": "Possible database password detected.",
    },    {
        "pii_type": "mysql_uri",
        "pattern": re.compile(
            r"\b((?:mysql|mariadb)://[^\s\"']+)",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "confidence": 0.95,
        "explanation": "Possible MySQL/MariaDB connection URI detected.",
    },
]


def _redact_secret(value: str) -> str:
    """
    Redact a secret while preserving a small hint for review.

    Examples:
    - short secrets become [SECRET REDACTED]
    - long secrets keep first 4 and last 4 chars
    """
    if len(value) < 12:
        return "[SECRET REDACTED]"

    return f"{value[:4]}...[REDACTED]...{value[-4:]}"


def _overlaps(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return a["start"] < b["end"] and b["start"] < a["end"]


def _dedupe_overlapping_detections(
    detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Remove overlapping detections.

    When two detections overlap, keep the longer match.
    """
    sorted_detections = sorted(
        detections,
        key=lambda item: (item["start"], -(item["end"] - item["start"])),
    )

    kept: list[dict[str, Any]] = []

    for detection in sorted_detections:
        overlapping_index = None

        for index, existing in enumerate(kept):
            if _overlaps(detection, existing):
                overlapping_index = index
                break

        if overlapping_index is None:
            kept.append(detection)
            continue

        existing = kept[overlapping_index]

        detection_length = detection["end"] - detection["start"]
        existing_length = existing["end"] - existing["start"]

        if detection_length > existing_length:
            kept[overlapping_index] = detection

    return sorted(kept, key=lambda item: item["start"])

def scan_secrets(text: str) -> list[dict[str, Any]]:
    """
    Scan text for common secrets and return LeakLens-compatible detections.
    """
    detections: list[dict[str, Any]] = []

    if not text:
        return detections

    for item in SECRET_PATTERNS:
        for match in item["pattern"].finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)

            start = match.start(1) if match.lastindex else match.start()
            end = match.end(1) if match.lastindex else match.end()

            detections.append(
                {
                    "pii_type": item["pii_type"],
                    "value": value,
                    "redacted": _redact_secret(value),
                    "severity": item["severity"],
                    "start": start,
                    "end": end,
                    "confidence": item["confidence"],
                    "explanation": item["explanation"],
                    "source": "secret_scanner",
                }
            )

    return _dedupe_overlapping_detections(detections)