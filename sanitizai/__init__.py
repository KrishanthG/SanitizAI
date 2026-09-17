"""
SanitizAI: Lightning-fast, zero-overhead local PII & secrets redaction engine.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Redact sensitive PII, developer API keys, and custom confidential tokens before
sending text to LLMs, log files, or external storage.
"""

from sanitizai.core import (
    PatternRule,
    SanitizAI,
    clean,
    mask_text,
    redact_pii,
    redact_secrets,
)

__version__ = "0.1.0"
__author__ = "Krishanth G"
__license__ = "MIT"

__all__ = [
    "SanitizAI",
    "clean",
    "redact_pii",
    "redact_secrets",
    "mask_text",
    "PatternRule",
    "__version__",
]
