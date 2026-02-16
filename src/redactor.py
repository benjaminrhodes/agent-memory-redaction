"""PII Redaction module."""

import re
from enum import Enum
from typing import Optional


class PIIType(Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"
    IP_ADDRESS = "ip_address"
    AWS_KEY = "aws_key"
    URL = "url"
    NAME = "name"
    ADDRESS = "address"


class Redactor:
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    PHONE_PATTERN = re.compile(r"(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}")
    SSN_PATTERN = re.compile(r"\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b")
    CREDIT_CARD_PATTERN = re.compile(r"\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b")
    API_KEY_PATTERN = re.compile(r"\b(?:sk[-_]?|api_)[A-Za-z0-9_]{6,}\b")
    IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
    AWS_ACCESS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    AWS_SECRET_KEY_PATTERN = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"]+[?&](?:token|key|api_key|secret|password)=[^\s<>"]+'
    )
    NAME_PATTERN = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")
    ADDRESS_PATTERN = re.compile(
        r"\b[0-9]+\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)[,.\s]+[A-Z][a-z]+(?:[,.\s]+[A-Z]{2}\s+[0-9]{5})?\b"
    )

    def __init__(self, pii_types: Optional[list[PIIType]] = None):
        self.pii_types = pii_types or list(PIIType)

    def redact(self, text: str) -> str:
        if not text:
            return text

        result = text
        if PIIType.ADDRESS in self.pii_types:
            result = self.ADDRESS_PATTERN.sub("[ADDRESS]", result)
        if PIIType.EMAIL in self.pii_types:
            result = self.EMAIL_PATTERN.sub("[EMAIL]", result)
        if PIIType.API_KEY in self.pii_types:
            result = self.API_KEY_PATTERN.sub("[API_KEY]", result)
        if PIIType.AWS_KEY in self.pii_types:
            result = self.AWS_ACCESS_KEY_PATTERN.sub("[AWS_KEY]", result)
            result = self.AWS_SECRET_KEY_PATTERN.sub("[AWS_KEY]", result)
        if PIIType.IP_ADDRESS in self.pii_types:
            result = self.IPV4_PATTERN.sub("[IP_ADDRESS]", result)
            result = self.IPV6_PATTERN.sub("[IP_ADDRESS]", result)
        if PIIType.URL in self.pii_types:
            result = self.URL_PATTERN.sub("[URL]", result)
        if PIIType.PHONE in self.pii_types:
            result = self.PHONE_PATTERN.sub("[PHONE]", result)
        if PIIType.SSN in self.pii_types:
            result = self.SSN_PATTERN.sub("[SSN]", result)
        if PIIType.CREDIT_CARD in self.pii_types:
            result = self.CREDIT_CARD_PATTERN.sub("[CREDIT_CARD]", result)
        if PIIType.NAME in self.pii_types:
            result = self.NAME_PATTERN.sub("[NAME]", result)

        return result
