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
  * **Generic Variable Assignments**: `api_key = "..."`, `gemini_api_key = '...'`, `mistral_key = "..."`, `Bearer `.
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
