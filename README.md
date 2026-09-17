# SanitizAI 🛡️⚡

[![PyPI Version](https://img.shields.io/pypi/v/sanitizai.svg?color=blue)](https://pypi.org/project/sanitizai/0.1.0/)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://pypi.org/project/sanitizai/0.1.0/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-brightgreen.svg)](SECURITY.md)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20(pure%20standard%20lib)-brightgreen)](#)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#)

> **Lightning-fast, zero-overhead, 100% local text sanitization engine for LLM prompts, application logs, and data storage.**

---

## Why SanitizAI?

In the era of Generative AI, passing unvetted user prompts, internal debug traces, or chat history to third-party LLM providers (OpenAI, Anthropic, Google Gemini, Groq, DeepSeek) introduces catastrophic privacy and security risks:

* **Exposed Developer Secrets**: Leaked OpenAI/Anthropic keys, GitHub PATs, and AWS credentials lead to compromised infrastructure and surprise cloud bills.
* **Compliance Violations**: Sending raw user PII (emails, phone numbers, credit card numbers, national IDs) to external APIs violates **GDPR**, **HIPAA**, **SOC 2**, and **PCI-DSS**.
* **Heavy Dependency Bloat**: Traditional redaction toolkits require gigabytes of PyTorch weights, Spacy NLP models, and hundreds of transitive dependencies that slow cold-starts and inflate Docker images.

**SanitizAI solves this with zero runtime dependencies.** Built purely on Python's optimized native `re` engine, it sanitizes text in **microseconds** right on your local CPU.

---

## Key Features

* ⚡ **Zero-Overhead & 100% Local**: No PyTorch, no HuggingFace, no remote network calls. Runs anywhere Python runs.
* 🛡️ **Comprehensive PII Redaction**:
  * Email addresses (`[EMAIL_REDACTED]`)
  * International & domestic phone numbers (US, India, global formats) (`[PHONE_REDACTED]`)
  * Credit card numbers with **Luhn Checksum Verification** to eliminate false positives on timestamps/order IDs (`[CREDIT_CARD_REDACTED]`)
  * National ID formats: Indian **Aadhaar** & **PAN**, US **SSN** (`[AADHAAR_REDACTED]`, `[PAN_REDACTED]`, `[SSN_REDACTED]`)
  * IPv4 addresses (`[IP_ADDRESS_REDACTED]`)
* 🔑 **Secret Key & Credential Masking**:
  * **All Major AI & LLM Providers**: OpenAI (`sk-`, `sk-proj-`), Google Gemini (`AQ` new & `AIza` legacy), Anthropic (`sk-ant-`), Groq (`gsk_`), Cohere (`c_`), Mistral AI (`m-`), and Vercel AI Gateway (`ai_`).
  * **Developer Credentials**: GitHub tokens (`ghp_...`, `github_pat_...`), AWS Access Key IDs (`AKIA...`), and secret keys in config lines.
  * **Cloud & Platform Tokens**: Slack tokens (`xoxb-...`), JWT tokens, and PEM Private Key blocks.
  * **Generic Variable Assignments**: `api_key = "..."`, `gemini_api_key = '...'`, `mistral_key = "..."`, `Bearer <token>`.
* 🧩 **Custom Extensibility**: Scrub enterprise-specific project codenames, custom regex patterns, or blacklist words with custom tags.
* 🌊 **Memory-Efficient Streaming**: Sanitize multi-gigabyte log files line-by-line with `clean_stream()` in $O(1)$ memory.
* 💻 **Dual CLI & API Architecture**: Clean programmatic Python API + standard Unix pipeline CLI (`cat app.log | sanitizai`).

---

## Supported AI Provider Keys

SanitizAI automatically identifies and scrubs developer credentials across all top-tier generative AI platforms:

| AI Provider | Key Prefix / Starting Characters | Details |
| :--- | :--- | :--- |
| **OpenAI (ChatGPT)** | `sk-proj-` or `sk-` | Traditional keys start with `sk-`, while newer project-scoped keys start with `sk-proj-`. |
| **Google AI Studio (Gemini)** | `AQ` (New) or `AIza` (Legacy) | Google migrated from legacy traffic keys starting with `AIza` to secure Authentication Keys starting with `AQ`. |
| **Anthropic (Claude)** | `sk-ant-` | Standard production keys start with explicit identifier `sk-ant-`. |
| **Groq** | `gsk_` | API keys generated from Groq Console strictly start with `gsk_`. |
| **Cohere** | `c_` or `co_` | Standard production keys lean on explicit prefix variations. |
| **Mistral AI** | `m-` | Varies depending on user vs. organization console setups. |
| **Vercel AI Gateway** | `ai_` | Edge gateway authentication tokens. |

---

## Installation

```bash
pip install sanitizai
```

*(Requires Python 3.10 or higher. Zero external runtime dependencies!)*

---

## Quick Start (Python API)

### 1. Basic Cleaning
```python
import sanitizai

raw_prompt = (
    "User alice.smith@enterprise.com reported an issue. "
    "Her phone is 9876543210 and she used API key sk-proj-1234567890abcdef1234567890abcdef1234567890. "
    "Server IP was 192.168.1.50."
)

clean_prompt = sanitizai.clean(raw_prompt)
print(clean_prompt)
```
**Output:**
```text
User [EMAIL_REDACTED] reported an issue. Her phone is [PHONE_REDACTED] and she used API key [SECRET_KEY_REDACTED]. Server IP was [IP_ADDRESS_REDACTED].
```

---

### 2. Selective Redaction (PII only or Secrets only)
```python
from sanitizai import redact_pii, redact_secrets

# Redact only PII, keep technical keys intact:
pii_safe = redact_pii("Contact me at dev@test.com with key sk-abc1234567890abcdef1234567890")
# -> "Contact me at [EMAIL_REDACTED] with key sk-abc1234567890abcdef1234567890"

# Redact only Secrets, keep user contact info:
secret_safe = redact_secrets("Contact me at dev@test.com with key sk-abc1234567890abcdef1234567890")
# -> "Contact me at dev@test.com with key [SECRET_KEY_REDACTED]"
```

---

### 3. Custom Blacklists & Custom Regex Patterns
```python
from sanitizai import SanitizAI

sanitizer = SanitizAI(
    blacklist_words=["ProjectTitan", "AcmeInternal"],
    blacklist_replacement="[INTERNAL_CONFIDENTIAL]",
    custom_patterns={
        r"TICKET-\d+": "[TICKET_REF]",
    }
)

text = "Working on ProjectTitan for AcmeInternal. Reference TICKET-4912."
print(sanitizer.clean(text))
# -> "Working on [INTERNAL_CONFIDENTIAL] for [INTERNAL_CONFIDENTIAL]. Reference [TICKET_REF]."
```

---

### 4. Non-Destructive Analysis (Inspection)
Inspect text and count detected sensitive entities without modifying the original string:
```python
from sanitizai import SanitizAI

sanitizer = SanitizAI()
stats = sanitizer.analyze("Call 555-123-4567 or email team@test.com with key sk-1234567890abcdef1234567890")

print(stats)
# -> {'openai_groq_anthropic_key': 1, 'email': 1, 'phone_intl': 1}
```

---

### 5. Large Stream Processing (Log Files / Generators)
```python
from sanitizai import SanitizAI

sanitizer = SanitizAI()

with open("massive_production.log", "r", encoding="utf-8") as infile, \
     open("sanitized.log", "w", encoding="utf-8") as outfile:
    for clean_line in sanitizer.clean_stream(infile):
        outfile.write(clean_line)
```

---

## Command Line Interface (CLI)

SanitizAI installs a standalone terminal executable `sanitizai`:

### Direct String Redaction
```bash
sanitizai "Contact support@example.com with key sk-1234567890abcdef1234567890"
# Output: Contact [EMAIL_REDACTED] with key [SECRET_KEY_REDACTED]
```

### Standard Input (Unix Pipeline)
```bash
# Pipe streaming logs directly
tail -f access.log | sanitizai

# Sanitize log file and redirect output
cat server.log | sanitizai > sanitized.log
```

### File Input & Output
```bash
sanitizai -i raw_records.txt -o clean_records.txt
```

### Display Redaction Statistics
```bash
sanitizai --stats "Report: admin@bank.com accessed 10.0.0.1 with key sk-1234567890abcdef1234567890"
```
**Output:**
```text
Report: [EMAIL_REDACTED] accessed [IP_ADDRESS_REDACTED] with key [SECRET_KEY_REDACTED]

--- SanitizAI Redaction Summary ---
  email: 1
  ipv4: 1
  openai_groq_anthropic_key: 1
  Total Redactions: 3
-----------------------------------
```

---

## Real-World Production Recipes

### Recipe 1: LLM Prompt Guard (OpenAI / Anthropic SDK)
```python
import os
import sanitizai
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def query_llm_safely(raw_user_input: str) -> str:
    # 1. Sanitize user prompt locally before it leaves your server
    safe_prompt = sanitizai.clean(raw_user_input)
    
    # 2. Dispatch sanitized prompt to LLM
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": safe_prompt}],
    )
    return response.choices[0].message.content
```

### Recipe 2: Automatic Python Logging Filter
```python
import logging
import sanitizai

class SanitizingLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitizai.clean(record.msg)
        return True

logger = logging.getLogger("production")
handler = logging.StreamHandler()
handler.addFilter(SanitizingLogFilter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Will automatically mask PII & secrets in your logs!
logger.info("Failed login for user john@doe.com with secret api_key='1234567890abcdef'")
```

---

## Performance & Benchmarks

| Toolkit | Runtime Dependencies | Cold Start Latency | Throughput (lines/sec) |
| :--- | :---: | :---: | :---: |
| **SanitizAI** | **0 (Pure Python)** | **< 1 ms** | **~60,000+** |
| Heavy NLP / ML Toolkits | PyTorch, Spacy, Transformers (~2.5 GB) | ~1,500 - 4,000 ms | ~800 |

*Zero supply-chain vulnerability footprint, zero container bloat, microsecond latency.*

---

## Running Tests

```bash
# Clone the repository
git clone https://github.com/sanitizai/sanitizai.git
cd SanitizAI

# Run tests with pytest
python -m pytest tests/ -v
```

---

## Contributing

We welcome community contributions, bug fixes, additional AI key formats, and performance enhancements!

* Please review our **[Contributing Guidelines](CONTRIBUTING.md)** for development environment setup, branching rules, and test requirements.
* Zero-dependency rule: All PRs must adhere to our zero external runtime dependencies architecture.

---

## Code of Conduct

SanitizAI is dedicated to providing a respectful, harassment-free, and inclusive experience for everyone. All participants are expected to adhere to our **[Code of Conduct](CODE_OF_CONDUCT.md)** (Contributor Covenant v2.1).

---

## Security

Security and vulnerability disclosures are handled with paramount urgency:

* Please review our **[Security Policy](SECURITY.md)** for threat modeling and supported versions.
* For responsible disclosure of security vulnerabilities or ReDoS vectors, please report via private GitHub Security Advisories or reach out directly on LinkedIn: **[krishanth-g](https://www.linkedin.com/in/krishanth-g)**. Do NOT open public issues for security vulnerabilities.

---

## Author & Maintainer

Maintained with ❤️ by **Krishanth G**
* LinkedIn: [krishanth-g](https://www.linkedin.com/in/krishanth-g)

---

## License

SanitizAI is distributed under the OSI-approved **[MIT License](LICENSE)**.

```text
Copyright (c) 2026 Krishanth G (https://www.linkedin.com/in/krishanth-g)
Licensed under the MIT License.
```
Free for personal, commercial, and enterprise use.
#   S a n i t i z A I  
 #   S a n i t i z A I  
 "# SanitizAI" 
