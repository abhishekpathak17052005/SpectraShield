"""
PII Redactor: Masks personally identifiable information in forensic reports.

Redacts:
- Email addresses
- Names and usernames
- IP addresses (optionally, for privacy)
- Phone numbers
- Domain names (optionally)
- File paths
- Specific identifiers (user IDs, ticket numbers)

Maintains forensic integrity by:
- Replacing with consistent markers
- Preserving structure (e.g., user@[REDACTED] instead of [REDACTED])
- Not removing critical technical information
- Tracking what was redacted
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class RedactionRule:
    """Defines a PII redaction rule."""
    name: str
    pattern: str  # Regex pattern
    replacement: str
    case_sensitive: bool = False
    enabled: bool = True


class PIIRedactor:
    """
    Redacts PII from forensic reports.
    
    Different redaction levels:
    - MINIMAL: Redact only email addresses
    - STANDARD: Email + names + some paths
    - STRICT: Email + names + IPs + domains + all paths
    """

    # Redaction levels
    LEVEL_MINIMAL = "minimal"
    LEVEL_STANDARD = "standard"
    LEVEL_STRICT = "strict"

    def __init__(self, level: str = LEVEL_STANDARD):
        """
        Initialize redactor with redaction level.
        
        Args:
            level: MINIMAL, STANDARD, or STRICT
        """
        self.level = level
        self.redacted_count = {}
        self.redaction_rules = self._build_rules()

    def _build_rules(self) -> List[RedactionRule]:
        """Build redaction rules based on level."""
        rules = []

        # Level: MINIMAL
        if self.level in [self.LEVEL_MINIMAL, self.LEVEL_STANDARD, self.LEVEL_STRICT]:
            # Email addresses - keep domain structure
            rules.append(RedactionRule(
                name="email_address",
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                replacement=lambda m: self._redact_email(m.group(0)),
                enabled=True
            ))

            # Common names (optional)
            rules.append(RedactionRule(
                name="user_mention",
                pattern=r'\b(?:user|admin|test|user[0-9]+)\b',
                replacement='[USER]',
                case_sensitive=False,
                enabled=True
            ))

        # Level: STANDARD and above
        if self.level in [self.LEVEL_STANDARD, self.LEVEL_STRICT]:
            # File paths (Windows and Unix) - properly escaped
            rules.append(RedactionRule(
                name="file_path",
                pattern=r'(?:[a-zA-Z]:\\|/)[^\s<>"{}|\\^`\[\]]*',
                replacement='[REDACTED_PATH]',
                enabled=True
            ))

            # Windows usernames in paths
            rules.append(RedactionRule(
                name="windows_user_path",
                pattern=r'C:\\Users\\[^\\]+',
                replacement='C:\\\\Users\\\\[REDACTED]',
                enabled=True
            ))

        # Level: STRICT
        if self.level == self.LEVEL_STRICT:
            # Public IP addresses (non-private)
            rules.append(RedactionRule(
                name="public_ip",
                pattern=r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                replacement=lambda m: self._redact_ip(m.group(0)),
                enabled=True
            ))

            # Domain names (keep TLD)
            rules.append(RedactionRule(
                name="domain_name",
                pattern=r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
                replacement=lambda m: self._redact_domain(m.group(0)),
                case_sensitive=False,
                enabled=True
            ))

            # Phone numbers
            rules.append(RedactionRule(
                name="phone_number",
                pattern=r'(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})',
                replacement='[PHONE]',
                enabled=True
            ))

        return rules

    @staticmethod
    def _redact_email(email: str) -> str:
        """
        Redact email address while preserving structure.
        
        Example: user.name@example.com → user@[REDACTED]
        """
        parts = email.split('@')
        if len(parts) == 2:
            local = parts[0]
            domain = parts[1]

            # Redact local part but keep first character
            first_char = local[0] if local else 'u'
            return f"{first_char}***@[REDACTED]"

        return "[EMAIL_REDACTED]"

    @staticmethod
    def _redact_ip(ip: str) -> str:
        """
        Redact IP address while preserving structure.
        
        Example: 203.0.113.50 → 203.0.113.***
        """
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.***"

        return "[IP_REDACTED]"

    @staticmethod
    def _redact_domain(domain: str) -> str:
        """
        Redact domain while preserving TLD.
        
        Example: secure-bank-online.com → [REDACTED].com
        """
        parts = domain.rsplit('.', 1)
        if len(parts) == 2:
            tld = parts[1]
            return f"[REDACTED].{tld}"

        return "[DOMAIN_REDACTED]"

    def redact_text(self, text: str) -> str:
        """
        Redact PII from text.
        
        Args:
            text: Text to redact
            
        Returns:
            Redacted text
        """
        if not text:
            return text

        redacted = text
        self.redacted_count = {}

        for rule in self.redaction_rules:
            if not rule.enabled:
                continue

            # Count occurrences
            matches = re.finditer(
                rule.pattern,
                redacted,
                re.IGNORECASE if not rule.case_sensitive else 0
            )

            count = sum(1 for _ in matches)
            if count > 0:
                self.redacted_count[rule.name] = count

            # Apply replacement
            if callable(rule.replacement):
                redacted = re.sub(
                    rule.pattern,
                    rule.replacement,
                    redacted,
                    flags=re.IGNORECASE if not rule.case_sensitive else 0
                )
            else:
                redacted = re.sub(
                    rule.pattern,
                    rule.replacement,
                    redacted,
                    flags=re.IGNORECASE if not rule.case_sensitive else 0
                )

        return redacted

    def redact_dict(self, data: Dict[str, Any], exclude_keys: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Recursively redact PII from dictionary.
        
        Args:
            data: Dictionary to redact
            exclude_keys: Keys to skip redaction (e.g., ['hash_sha256'])
            
        Returns:
            Dictionary with redacted values
        """
        if exclude_keys is None:
            exclude_keys = ['hash_sha256', 'asn', 'abuse_confidence', 'threat_reports']

        redacted = {}

        for key, value in data.items():
            if key in exclude_keys:
                redacted[key] = value
            elif isinstance(value, str):
                redacted[key] = self.redact_text(value)
            elif isinstance(value, dict):
                redacted[key] = self.redact_dict(value, exclude_keys)
            elif isinstance(value, list):
                redacted[key] = [
                    self.redact_text(item) if isinstance(item, str)
                    else self.redact_dict(item, exclude_keys) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                redacted[key] = value

        return redacted

    def redact_forensic_data(self, forensic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive fields from forensic data.
        
        Preserves technical information (IPs, domains) unless STRICT mode.
        Redacts user identities and personal information.
        
        Args:
            forensic_data: Forensic analysis data
            
        Returns:
            Redacted forensic data
        """
        # Keys to skip (technical/non-PII)
        skip_keys = ['hash_sha256', 'asn', 'abuse_confidence', 'threat_reports', 'ip', 'organization']

        redacted = {}

        for key, value in forensic_data.items():
            if key == 'email_metadata':
                # Redact email addresses and subject
                redacted[key] = {
                    'sender': self.redact_text(value.get('sender', '')) if 'sender' in value else value.get('sender'),
                    'recipient': self.redact_text(value.get('recipient', '')) if 'recipient' in value else value.get('recipient'),
                    'subject': self.redact_text(value.get('subject', '')) if 'subject' in value else value.get('subject'),
                    'timestamp': value.get('timestamp'),  # Don't redact
                    'message_id': value.get('message_id'),  # Don't redact
                    'hash_sha256': value.get('hash_sha256'),  # Don't redact
                }
            elif key == 'case_id':
                redacted[key] = value  # Don't redact case ID
            elif key == 'analysis_timestamp':
                redacted[key] = value  # Don't redact timestamp
            elif isinstance(value, dict):
                redacted[key] = self.redact_dict(value, skip_keys)
            elif isinstance(value, str):
                redacted[key] = self.redact_text(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self.redact_text(item) if isinstance(item, str)
                    else self.redact_dict(item, skip_keys) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                redacted[key] = value

        return redacted

    def get_redaction_summary(self) -> Dict[str, int]:
        """Get summary of what was redacted."""
        return self.redacted_count.copy()

    def create_redaction_header(self) -> str:
        """
        Create header text for redacted reports.
        
        Returns:
            Formatted header text
        """
        level_desc = {
            self.LEVEL_MINIMAL: "Email addresses",
            self.LEVEL_STANDARD: "Email addresses, user identifiers, file paths",
            self.LEVEL_STRICT: "Email addresses, domains, IPs, phone numbers, and all identifiers"
        }

        description = level_desc.get(self.level, "Unknown")

        return (
            f"*** PII REDACTION APPLIED ***\n"
            f"Redaction Level: {self.level.upper()}\n"
            f"Redacted Information: {description}\n"
            f"Technical Information (IPs, ASNs, hashes) preserved for forensic analysis\n"
            f"*** END REDACTION NOTICE ***"
        )


class RedactionValidator:
    """
    Validates that redaction has been applied correctly.
    Checks for remaining PII patterns in redacted data.
    """

    # Patterns that should NOT appear in redacted text
    DANGEROUS_PATTERNS = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
        (r'(?:user|admin)\w*', 'user_identifier'),
    ]

    @staticmethod
    def validate_redaction(text: str) -> Tuple[bool, List[str]]:
        """
        Validate that text doesn't contain unredacted PII.
        
        Args:
            text: Text to validate
            
        Returns:
            (is_valid, list_of_issues)
        """
        issues = []

        for pattern, pattern_name in RedactionValidator.DANGEROUS_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                issues.append(f"Found unredacted {pattern_name}: {matches[0]}")

        return len(issues) == 0, issues

    @staticmethod
    def validate_redaction_dict(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Recursively validate redaction in dictionary.
        
        Args:
            data: Dictionary to validate
            
        Returns:
            (is_valid, list_of_issues)
        """
        all_issues = []

        for key, value in data.items():
            if isinstance(value, str):
                valid, issues = RedactionValidator.validate_redaction(value)
                if not valid:
                    all_issues.extend([f"{key}: {issue}" for issue in issues])
            elif isinstance(value, dict):
                valid, issues = RedactionValidator.validate_redaction_dict(value)
                if not valid:
                    all_issues.extend(issues)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        valid, issues = RedactionValidator.validate_redaction(item)
                        if not valid:
                            all_issues.extend(issues)
                    elif isinstance(item, dict):
                        valid, issues = RedactionValidator.validate_redaction_dict(item)
                        if not valid:
                            all_issues.extend(issues)

        return len(all_issues) == 0, all_issues
