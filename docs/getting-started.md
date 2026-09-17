# Getting Started 🚀

This guide walks you through installing **SanitizAI** and sanitizing text streams in Python in under two minutes.

---

## Installation

SanitizAI is available as an official package on [PyPI](https://pypi.org/project/sanitizai/0.1.0/):

```bash
pip install sanitizai
```

### System Requirements

* **Python**: `3.10`, `3.11`, `3.12`, `3.13`, or `3.14`
* **Operating System**: macOS, Linux, or Windows
* **Dependencies**: **Zero** external runtime dependencies! SanitizAI executes purely on Python's built-in standard library.

---

## Quick Start (Copy & Paste)

Here is a complete, runnable example showing how to redact PII, API keys, and sensitive tokens from user prompts:

```python
import sanitizai

# Sample raw text containing PII, AI keys, and IP addresses
raw_text = (
    "User alex@enterprise.com reported an incident with phone +1 555-019-2834. "
    "He exposed his OpenAI key sk-proj-1234567890abcdef1234567890abcdef1234567890 "
    "and Gemini key AQ1234567890abcdef1234567890abcdef on server 192.168.1.50."
)

# Sanitize text
clean_text = sanitizai.clean(raw_text)

print(clean_text)
```

### Output

```text
User [EMAIL_REDACTED] reported an incident with phone [PHONE_REDACTED]. He exposed his OpenAI key [SECRET_KEY_REDACTED] and Gemini key [SECRET_KEY_REDACTED] on server [IP_ADDRESS_REDACTED].
```

---

## Selective Redaction

Need to scrub only contact data while keeping internal API keys intact for technical debugging? Or vice versa? Use our dedicated convenience helpers:

=== "PII Only"
    ```python
    from sanitizai import redact_pii

    text = "Send alert to dev@corp.com regarding key sk-1234567890abcdef1234567890"
    print(redact_pii(text))
    # -> "Send alert to [EMAIL_REDACTED] regarding key sk-1234567890abcdef1234567890"
    ```

=== "Secrets Only"
    ```python
    from sanitizai import redact_secrets

    text = "Send alert to dev@corp.com regarding key sk-1234567890abcdef1234567890"
    print(redact_secrets(text))
    # -> "Send alert to dev@corp.com regarding key [SECRET_KEY_REDACTED]"
    ```

---

## Custom Blacklists & Regex Patterns

Enterprise environments frequently require scrubbing proprietary project codenames or ticket numbers. You can instantiate `SanitizAI` with custom configurations:

```python
from sanitizai import SanitizAI

sanitizer = SanitizAI(
    # Mask specific corporate codenames or forbidden words
    blacklist_words=["ProjectTitan", "AcmeInternal"],
    blacklist_replacement="[CONFIDENTIAL_PROJECT]",
    # Mask custom regular expression formats
    custom_patterns={
        r"TICKET-\d+": "[TICKET_REF]",
        r"EMPLOYEE-\d{4}": "[EMP_ID]",
    }
)

log_message = "EMPLOYEE-4819 discussed ProjectTitan under TICKET-9921."
print(sanitizer.clean(log_message))
```

### Output

```text
[EMP_ID] discussed [CONFIDENTIAL_PROJECT] under [TICKET_REF].
```

---

## Next Steps

* 📖 Explore the full Python class and method documentation in the **[API Reference](api-reference.md)**.
* 💻 Learn how to use SanitizAI directly in Unix pipelines and shell scripts in the **[CLI Guide](cli-guide.md)**.
