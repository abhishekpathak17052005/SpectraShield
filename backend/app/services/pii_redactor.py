import re
import copy
from typing import Tuple, List, Dict, Any


def luhn_validate(card_number_str: str) -> bool:
    """Verifies standard Luhn checksum for credit/debit card numbers."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum % 10) == 0


class PiiRedactor:
    """
    Automated PII Sanitization Engine conforming to GDPR, DPDP Act (India), and HIPAA.
    Sanitizes sensitive financial, national identifier, and credential tokens
    for court dossier and STIX exports while preserving raw evidence integrity.
    """

    # Regex patterns
    CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
    IBAN_REGEX = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")
    SSN_REGEX = re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b")
    AADHAAR_REGEX = re.compile(r"\b[2-9]\d{3}[ -]\d{4}[ -]\d{4}\b")
    INDIAN_PAN_REGEX = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
    PASSWORD_LEAK_REGEX = re.compile(r"(?i)(?:password|passwd|pwd|secret|token)\s*[:=]\s*([^\s,;]+)")
    PHONE_REGEX = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

    def redact_text(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Sanitizes sensitive PII tokens from string text.
        Returns: (sanitized_text, redaction_manifest)
        """
        if not text:
            return "", []

        sanitized = text
        manifest: List[Dict[str, Any]] = []

        # 1. Credit Cards
        for match in self.CREDIT_CARD_REGEX.finditer(text):
            candidate = match.group(0)
            digits_only = re.sub(r"\D", "", candidate)
            if luhn_validate(digits_only):
                last4 = digits_only[-4:]
                replacement = f"[REDACTED_CARD_****{last4}]"
                sanitized = sanitized.replace(candidate, replacement)
                manifest.append({"type": "CREDIT_CARD", "original_len": len(candidate), "masked_as": replacement})

        # 2. IBAN & Bank Accounts
        for match in self.IBAN_REGEX.finditer(sanitized):
            candidate = match.group(0)
            replacement = f"[REDACTED_IBAN_{candidate[:2]}****{candidate[-4:]}]"
            sanitized = sanitized.replace(candidate, replacement)
            manifest.append({"type": "BANK_IBAN", "masked_as": replacement})

        # 3. National Identity: SSN (US)
        for match in self.SSN_REGEX.finditer(sanitized):
            candidate = match.group(0)
            replacement = "[REDACTED_SSN_***-**-****]"
            sanitized = sanitized.replace(candidate, replacement)
            manifest.append({"type": "NATIONAL_ID_SSN", "masked_as": replacement})

        # 4. National Identity: Aadhaar (India)
        for match in self.AADHAAR_REGEX.finditer(sanitized):
            candidate = match.group(0)
            replacement = "[REDACTED_AADHAAR_****-****-****]"
            sanitized = sanitized.replace(candidate, replacement)
            manifest.append({"type": "NATIONAL_ID_AADHAAR", "masked_as": replacement})

        # 5. National Identity: PAN (India)
        for match in self.INDIAN_PAN_REGEX.finditer(sanitized):
            candidate = match.group(0)
            # Only match if looks like genuine PAN and not general uppercase word
            if candidate not in {"CLASS", "TABLE", "TOTAL", "PRICE", "STATE", "ERROR"}:
                replacement = "[REDACTED_PAN_*****0000*]"
                sanitized = sanitized.replace(candidate, replacement)
                manifest.append({"type": "TAX_ID_PAN", "masked_as": replacement})

        # 6. Credentials / Passwords
        for match in self.PASSWORD_LEAK_REGEX.finditer(sanitized):
            secret = match.group(1)
            if len(secret) > 3 and not secret.startswith("[REDACTED"):
                sanitized = sanitized.replace(secret, "[REDACTED_CREDENTIAL]")
                manifest.append({"type": "CREDENTIAL", "masked_as": "[REDACTED_CREDENTIAL]"})

        # 7. Telephone Numbers
        for match in self.PHONE_REGEX.finditer(sanitized):
            candidate = match.group(0)
            if len(re.sub(r"\D", "", candidate)) >= 10:
                replacement = "[REDACTED_PHONE_***-****]"
                sanitized = sanitized.replace(candidate, replacement)
                manifest.append({"type": "PHONE_NUMBER", "masked_as": replacement})

        return sanitized, manifest

    def sanitize_case_data(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Creates a sanitized deep copy of case data for court/third-party export.
        Preserves original SHA-256 evidence vault hash while masking body and subject text.
        """
        sanitized = copy.deepcopy(case_data)

        total_manifest = []

        # Redact raw eml or body text
        if "raw_eml" in sanitized and sanitized["raw_eml"]:
            sanitized["raw_eml"], m = self.redact_text(sanitized["raw_eml"])
            total_manifest.extend(m)

        if "reasoning_summary" in sanitized and sanitized["reasoning_summary"]:
            sanitized["reasoning_summary"], m = self.redact_text(sanitized["reasoning_summary"])
            total_manifest.extend(m)

        if "subject" in sanitized and sanitized["subject"]:
            sanitized["subject"], m = self.redact_text(sanitized["subject"])
            total_manifest.extend(m)

        sanitized["is_redacted"] = True
        sanitized["redaction_manifest"] = total_manifest
        sanitized["redaction_compliance"] = ["ISO/IEC 27037", "GDPR Art 32", "DPDP Act 2023"]

        return sanitized


pii_redactor = PiiRedactor()
