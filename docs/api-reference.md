# API Reference 📚

Complete technical specification of all functions, classes, and options in the `sanitizai` Python library.

---

## Convenience Functions

### `clean()`

The primary all-in-one sanitization helper function.

```python
def clean(
    text: str,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    custom_patterns: Optional[Dict[Union[str, Pattern[str]], str]] = None,
    blacklist_words: Optional[Sequence[str]] = None,
    blacklist_replacement: str = "[CONFIDENTIAL_REDACTED]",
) -> str
```

#### Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `text` | `str` | *Required* | Input text string to sanitize. |
| `mask_pii` | `bool` | `True` | Redacts emails, phone numbers, credit cards, Aadhaar, PAN, SSN, and IPv4 addresses. |
| `mask_secrets` | `bool` | `True` | Redacts OpenAI, Gemini, Anthropic, Groq, Cohere, Mistral, Vercel, GitHub, and AWS keys. |
| `custom_patterns` | `dict` | `None` | Mapping of custom regex patterns (string or `re.compile`) to replacement tags. |
| `blacklist_words` | `list` | `None` | Sequence of sensitive words or phrases to mask case-insensitively. |
| `blacklist_replacement` | `str` | `"[CONFIDENTIAL_REDACTED]"` | Replacement tag for blacklisted words. |

#### Example

```python
import sanitizai

text = "User bob@test.com with key sk-proj-1234567890abcdef1234567890abcdef"
clean_text = sanitizai.clean(text)
print(clean_text)
```

```text
User [EMAIL_REDACTED] with key [SECRET_KEY_REDACTED]
```

---

### `redact_pii()`

Convenience helper to redact **only** Personal Identifiable Information while preserving developer keys.

```python
def redact_pii(text: str) -> str
```

#### Example

```python
from sanitizai import redact_pii

text = "Contact alice@corp.com with AWS Key AKIAIOSFODNN7EXAMPLE"
print(redact_pii(text))
```

```text
Contact [EMAIL_REDACTED] with AWS Key AKIAIOSFODNN7EXAMPLE
```

---

### `redact_secrets()`

Convenience helper to redact **only** developer secrets and AI keys while preserving user contact data.

```python
def redact_secrets(text: str) -> str
```

#### Example

```python
from sanitizai import redact_secrets

text = "Contact alice@corp.com with AWS Key AKIAIOSFODNN7EXAMPLE"
print(redact_secrets(text))
```

```text
Contact alice@corp.com with AWS Key [SECRET_KEY_REDACTED]
```

---

## Class: `SanitizAI`

The core configurable redaction engine. Use an instance of this class when configuring reusable pipelines, custom blacklists, streaming, or inspection.

```python
class SanitizAI:
    def __init__(
        self,
        mask_pii: bool = True,
        mask_secrets: bool = True,
        custom_patterns: Optional[Dict[Union[str, Pattern[str]], str]] = None,
        blacklist_words: Optional[Sequence[str]] = None,
        blacklist_replacement: str = "[CONFIDENTIAL_REDACTED]",
        validate_credit_cards: bool = True,
    ) -> None
```

#### Constructor Arguments

* **`mask_pii`** (*bool*): Enable/disable PII rules. Default: `True`.
* **`mask_secrets`** (*bool*): Enable/disable API key and secret rules. Default: `True`.
* **`custom_patterns`** (*dict*): Custom dictionary mapping regex to tag. Default: `{}`.
* **`blacklist_words`** (*sequence*): Sequence of confidential terms. Default: `[]`.
* **`blacklist_replacement`** (*str*): Tag replacing blacklisted words. Default: `"[CONFIDENTIAL_REDACTED]"`.
* **`validate_credit_cards`** (*bool*): When `True`, validates card candidates using the **Luhn Algorithm** to prevent false positives on order IDs. Default: `True`.

---

### Methods

#### `clean()`

Sanitizes a single string using the compiled rule set.

```python
def clean(self, text: str) -> str
```

---

#### `clean_stream()`

Memory-efficient streaming generator for massive log files, HTTP chunks, or real-time pipelines. Yields sanitized lines in $O(1)$ memory.

```python
def clean_stream(self, lines: Iterable[str]) -> Iterator[str]
```

##### Example

```python
from sanitizai import SanitizAI

sanitizer = SanitizAI()

with open("gigantic_server.log", "r", encoding="utf-8") as infile, \
     open("sanitized_server.log", "w", encoding="utf-8") as outfile:
    for clean_line in sanitizer.clean_stream(infile):
        outfile.write(clean_line)
```

---

#### `analyze()`

Non-destructive inspection method that reports detection frequencies without modifying the text.

```python
def analyze(self, text: str) -> Dict[str, int]
```

##### Example

```python
from sanitizai import SanitizAI

sanitizer = SanitizAI()
prompt = (
    "Email: team@dev.com, "
    "Server: 10.0.0.1, "
    "Gemini Key: AQ1234567890abcdef1234567890abcdef, "
    "Mistral Key: m-1234567890abcdef1234567890abcdef"
)

stats = sanitizer.analyze(prompt)
print(stats)
```

```text
{
    'email': 1,
    'ipv4': 1,
    'gemini_key': 1,
    'mistral_key': 1
}
```

---

## Supported AI Provider Keys

SanitizAI includes pre-compiled, optimized regex patterns for all modern LLM providers:

| AI Provider | Key Prefix / Starting Pattern | Replacement Tag |
| :--- | :--- | :--- |
| **OpenAI (ChatGPT)** | `sk-` or `sk-proj-` | `[SECRET_KEY_REDACTED]` |
| **Google AI Studio (Gemini)** | `AQ` (New) or `AIza` (Legacy) | `[SECRET_KEY_REDACTED]` |
| **Anthropic (Claude)** | `sk-ant-` | `[SECRET_KEY_REDACTED]` |
| **Groq Console** | `gsk_` | `[SECRET_KEY_REDACTED]` |
| **Cohere** | `c_` or `co_` | `[SECRET_KEY_REDACTED]` |
| **Mistral AI** | `m-` | `[SECRET_KEY_REDACTED]` |
| **Vercel AI Gateway** | `ai_` | `[SECRET_KEY_REDACTED]` |
| **Generic Assignments** | `api_key = "..."`, `gemini_key = '...'`, `Bearer <token>` | `[SECRET_KEY_REDACTED]` |
