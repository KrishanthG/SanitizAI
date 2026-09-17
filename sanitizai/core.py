"""
SanitizAI - Core Redaction Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Lightning-fast, zero-overhead, 100% local text sanitization utility for
PII, API keys, credentials, and custom tokens.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import (
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Pattern,
    Sequence,
    Union,
)

__all__ = [
    "SanitizAI",
    "clean",
    "redact_pii",
    "redact_secrets",
    "mask_text",
    "PatternRule",
]


def _is_luhn_valid(number_str: str) -> bool:
    """Validate a credit card number string using the Luhn checksum algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


@dataclass(frozen=True)
class PatternRule:
    """Represents a compiled redaction rule."""

    name: str
    category: str  # 'pii' or 'secrets' or 'custom'
    pattern: Pattern[str]
    replacement: str
    validator: Optional[Callable[[str], bool]] = None
    is_assignment: bool = False  # True if pattern captures (prefix)(secret)(suffix)


# ==============================================================================
# DEFAULT REGEX DEFINITIONS (Pre-compiled for ultra-fast local execution)
# ==============================================================================

# PII Patterns
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Credit Cards: 13 to 19 digits formatted with spaces or hyphens, or contiguous
RE_CREDIT_CARD = re.compile(
    r"\b(?:\d{4}[ -]){3}\d{1,7}\b|\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b|\b\d{13,19}\b"
)

# Indian PII
RE_AADHAAR = re.compile(
    r"\b[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?![ -]?\d)\b"
)
RE_PAN = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
)

# US SSN (Social Security Number)
RE_SSN = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"
)

# Phone Numbers: Matches US/NANP, Indian (+91/0 10-digit), and generic international formats
RE_PHONE_INTL = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
RE_PHONE_IN = re.compile(
    r"(?:(?:\+91|91|0)[-.\s]?)?[6-9]\d{4}[-.\s]?\d{5}\b"
)

# IP Addresses (IPv4)
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Secrets & Developer Credentials
# Modern GenAI & AI Provider API Keys
RE_OPENAI_KEY = re.compile(
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"
)
RE_ANTHROPIC_KEY = re.compile(
    r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"
)
RE_GROQ_KEY = re.compile(
    r"\bgsk_[A-Za-z0-9_-]{20,}\b"
)
RE_GEMINI_KEY = re.compile(
    r"\b(?:AQ[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z\-_]{30,40})\b"
)
RE_GOOGLE_API_KEY = RE_GEMINI_KEY  # Alias for backward compatibility
RE_COHERE_KEY = re.compile(
    r"\b(?:c_|co_)[A-Za-z0-9_-]{20,}\b"
)
RE_MISTRAL_KEY = re.compile(
    r"\bm-[A-Za-z0-9_-]{20,}\b"
)
RE_VERCEL_AI_KEY = re.compile(
    r"\bai_[A-Za-z0-9_-]{20,}\b"
)

# GitHub Tokens (Personal access tokens, OAuth, App tokens, fine-grained PAT)
RE_GITHUB_TOKEN = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"
)

# AWS Credentials
RE_AWS_ACCESS_KEY = re.compile(
    r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"
)
RE_AWS_SECRET_KEY = re.compile(
    r"(?i)\b((?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?)([A-Za-z0-9/+=]{40})(['\"]?)"
)

# Slack Tokens
RE_SLACK_TOKEN = re.compile(
    r"\bxox[baprs]-[0-9A-Za-z\-]{10,80}\b"
)

# JSON Web Token (JWT)
RE_JWT_TOKEN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

# Private Key PEM Blocks
RE_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+PRIVATE KEY-----"
)

# Generic Variable Secret Assignments (e.g. api_key="secret", openai_api_key="...", auth_token: 'secret')
RE_GENERIC_SECRET_ASSIGN = re.compile(
    r"(?i)\b((?:[A-Za-z0-9_-]*(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|app[_-]?secret)|password|client[_-]?secret)\s*[:=]\s*['\"]?)([A-Za-z0-9_\-.~+/=]{8,})(['\"]?)"
)

# Bearer Authorization Tokens
RE_BEARER_TOKEN = re.compile(
    r"(?i)\b(Bearer\s+)([A-Za-z0-9_\-.~+/=]{16,})\b"
)


class SanitizAI:
    """
    Lightning-fast, zero-overhead text sanitization and redaction engine.
    100% local with no third-party ML dependencies.
    """

    def __init__(
        self,
        mask_pii: bool = True,
        mask_secrets: bool = True,
        custom_patterns: Optional[Dict[Union[str, Pattern[str]], str]] = None,
        blacklist_words: Optional[Sequence[str]] = None,
        blacklist_replacement: str = "[CONFIDENTIAL_REDACTED]",
        validate_credit_cards: bool = True,
    ) -> None:
        """
        Initialize the SanitizAI engine.

        :param mask_pii: Whether to redact Personal Identifiable Information.
        :param mask_secrets: Whether to redact developer API keys, tokens & credentials.
        :param custom_patterns: Dictionary mapping regex pattern (str or compiled) to replacement tag.
        :param blacklist_words: Sequence of confidential words or phrases to mask.
        :param blacklist_replacement: Replacement tag for blacklisted words.
        :param validate_credit_cards: If True, uses Luhn algorithm validation on prospective card numbers.
        """
        self.mask_pii = mask_pii
        self.mask_secrets = mask_secrets
        self.custom_patterns = custom_patterns or {}
        self.blacklist_words = list(blacklist_words or [])
        self.blacklist_replacement = blacklist_replacement
        self.validate_credit_cards = validate_credit_cards

        self._rules: List[PatternRule] = []
        self._blacklist_rule: Optional[PatternRule] = None
        self._build_rules()

    def _build_rules(self) -> None:
        """Compile and assemble the ordered ruleset."""
        rules: List[PatternRule] = []

        # 1. Custom User Patterns (highest priority)
        for pat, repl in self.custom_patterns.items():
            compiled = pat if isinstance(pat, Pattern) else re.compile(pat)
            rules.append(
                PatternRule(
                    name=f"custom_{compiled.pattern[:15]}",
                    category="custom",
                    pattern=compiled,
                    replacement=repl,
                )
            )

        # 2. Blacklist Words
        if self.blacklist_words:
            sorted_words = sorted(
                (w.strip() for w in self.blacklist_words if w.strip()),
                key=len,
                reverse=True,
            )
            if sorted_words:
                escaped = [re.escape(w) for w in sorted_words]
                blacklist_pat = re.compile(
                    r"(?i)\b(?:" + "|".join(escaped) + r")\b"
                )
                self._blacklist_rule = PatternRule(
                    name="blacklist_words",
                    category="custom",
                    pattern=blacklist_pat,
                    replacement=self.blacklist_replacement,
                )

        # 3. Secret Keys & Developer Credentials
        if self.mask_secrets:
            rules.append(
                PatternRule(
                    name="pem_private_key",
                    category="secrets",
                    pattern=RE_PEM_PRIVATE_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="aws_secret_key",
                    category="secrets",
                    pattern=RE_AWS_SECRET_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                    is_assignment=True,
                )
            )
            rules.append(
                PatternRule(
                    name="generic_secret_assignment",
                    category="secrets",
                    pattern=RE_GENERIC_SECRET_ASSIGN,
                    replacement="[SECRET_KEY_REDACTED]",
                    is_assignment=True,
                )
            )
            rules.append(
                PatternRule(
                    name="bearer_token",
                    category="secrets",
                    pattern=RE_BEARER_TOKEN,
                    replacement="[SECRET_KEY_REDACTED]",
                    is_assignment=True,
                )
            )
            # Modern AI Provider API Keys
            rules.append(
                PatternRule(
                    name="openai_key",
                    category="secrets",
                    pattern=RE_OPENAI_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="anthropic_key",
                    category="secrets",
                    pattern=RE_ANTHROPIC_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="groq_key",
                    category="secrets",
                    pattern=RE_GROQ_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="gemini_key",
                    category="secrets",
                    pattern=RE_GEMINI_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="cohere_key",
                    category="secrets",
                    pattern=RE_COHERE_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="mistral_key",
                    category="secrets",
                    pattern=RE_MISTRAL_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="vercel_ai_key",
                    category="secrets",
                    pattern=RE_VERCEL_AI_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="github_token",
                    category="secrets",
                    pattern=RE_GITHUB_TOKEN,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="aws_access_key",
                    category="secrets",
                    pattern=RE_AWS_ACCESS_KEY,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="slack_token",
                    category="secrets",
                    pattern=RE_SLACK_TOKEN,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="jwt_token",
                    category="secrets",
                    pattern=RE_JWT_TOKEN,
                    replacement="[SECRET_KEY_REDACTED]",
                )
            )

        # 4. PII Redaction
        if self.mask_pii:
            rules.append(
                PatternRule(
                    name="email",
                    category="pii",
                    pattern=RE_EMAIL,
                    replacement="[EMAIL_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="credit_card",
                    category="pii",
                    pattern=RE_CREDIT_CARD,
                    replacement="[CREDIT_CARD_REDACTED]",
                    validator=_is_luhn_valid if self.validate_credit_cards else None,
                )
            )
            rules.append(
                PatternRule(
                    name="aadhaar",
                    category="pii",
                    pattern=RE_AADHAAR,
                    replacement="[AADHAAR_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="pan_card",
                    category="pii",
                    pattern=RE_PAN,
                    replacement="[PAN_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="ssn",
                    category="pii",
                    pattern=RE_SSN,
                    replacement="[SSN_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="phone_in",
                    category="pii",
                    pattern=RE_PHONE_IN,
                    replacement="[PHONE_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="phone_intl",
                    category="pii",
                    pattern=RE_PHONE_INTL,
                    replacement="[PHONE_REDACTED]",
                )
            )
            rules.append(
                PatternRule(
                    name="ipv4",
                    category="pii",
                    pattern=RE_IPV4,
                    replacement="[IP_ADDRESS_REDACTED]",
                )
            )

        self._rules = rules

    def clean(self, text: str) -> str:
        """
        Sanitize input text by redacting all enabled PII, secrets, and custom rules.

        :param text: The input string to sanitize.
        :return: Sanitized string with confidential values replaced by placeholders.
        """
        if not text:
            return ""

        result = text

        if self._blacklist_rule:
            result = self._blacklist_rule.pattern.sub(
                self._blacklist_rule.replacement, result
            )

        for rule in self._rules:
            if rule.is_assignment:
                def make_repl(m: re.Match[str], repl: str = rule.replacement) -> str:
                    prefix = m.group(1)
                    suffix = m.group(3) if len(m.groups()) >= 3 else ""
                    return f"{prefix}{repl}{suffix}"

                result = rule.pattern.sub(make_repl, result)

            elif rule.validator:
                def validate_and_replace(
                    m: re.Match[str],
                    v: Callable[[str], bool] = rule.validator,
                    repl: str = rule.replacement,
                ) -> str:
                    matched_str = m.group(0)
                    if matched_str.startswith("[") and matched_str.endswith("]"):
                        return matched_str
                    if v(matched_str):
                        return repl
                    return matched_str

                result = rule.pattern.sub(validate_and_replace, result)

            else:
                def safe_replace(
                    m: re.Match[str], repl: str = rule.replacement
                ) -> str:
                    matched = m.group(0)
                    if matched.startswith("[") and matched.endswith("]"):
                        return matched
                    return repl

                result = rule.pattern.sub(safe_replace, result)

        return result

    def clean_stream(self, lines: Iterable[str]) -> Iterator[str]:
        """
        Memory-efficient streaming sanitization for logs, file readers, or network pipes.
        Yields sanitized lines on-the-fly with O(1) memory overhead.

        :param lines: Iterable of strings/lines.
        :return: Generator yielding sanitized strings.
        """
        for line in lines:
            yield self.clean(line)

    def analyze(self, text: str) -> Dict[str, int]:
        """
        Inspect the input text and report counts of sensitive elements detected
        without modifying the text.

        :param text: The input string to inspect.
        :return: Dictionary mapping rule names to match counts.
        """
        if not text:
            return {}

        stats: Dict[str, int] = {}

        if self._blacklist_rule:
            matches = len(self._blacklist_rule.pattern.findall(text))
            if matches > 0:
                stats["blacklist_words"] = matches

        for rule in self._rules:
            if rule.validator:
                count = sum(
                    1
                    for m in rule.pattern.finditer(text)
                    if not (m.group(0).startswith("[") and m.group(0).endswith("]"))
                    and rule.validator(m.group(0))
                )
            else:
                count = sum(
                    1
                    for m in rule.pattern.finditer(text)
                    if not (m.group(0).startswith("[") and m.group(0).endswith("]"))
                )
            if count > 0:
                stats[rule.name] = count

        return stats


# ==============================================================================
# CONVENIENCE MODULE FUNCTIONS
# ==============================================================================

_DEFAULT_SANITIZER = SanitizAI()
_PII_ONLY_SANITIZER = SanitizAI(mask_pii=True, mask_secrets=False)
_SECRETS_ONLY_SANITIZER = SanitizAI(mask_pii=False, mask_secrets=True)


def clean(
    text: str,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    custom_patterns: Optional[Dict[Union[str, Pattern[str]], str]] = None,
    blacklist_words: Optional[Sequence[str]] = None,
    blacklist_replacement: str = "[CONFIDENTIAL_REDACTED]",
) -> str:
    """
    Sanitize text using default or customized SanitizAI configuration.

    :param text: Input string to clean.
    :param mask_pii: Whether to redact PII (emails, phones, cards, Aadhaar, PAN, SSN, IP).
    :param mask_secrets: Whether to redact API keys and credentials.
    :param custom_patterns: Optional dict of regex: replacement.
    :param blacklist_words: Optional list of confidential terms.
    :param blacklist_replacement: Replacement tag for blacklist words.
    :return: Sanitized string.
    """
    if (
        mask_pii
        and mask_secrets
        and not custom_patterns
        and not blacklist_words
    ):
        return _DEFAULT_SANITIZER.clean(text)

    sanitizer = SanitizAI(
        mask_pii=mask_pii,
        mask_secrets=mask_secrets,
        custom_patterns=custom_patterns,
        blacklist_words=blacklist_words,
        blacklist_replacement=blacklist_replacement,
    )
    return sanitizer.clean(text)


def redact_pii(text: str) -> str:
    """Convenience helper to redact only PII elements."""
    return _PII_ONLY_SANITIZER.clean(text)


def redact_secrets(text: str) -> str:
    """Convenience helper to redact only Secret keys and credentials."""
    return _SECRETS_ONLY_SANITIZER.clean(text)


mask_text = clean
