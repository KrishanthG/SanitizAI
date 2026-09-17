# Welcome to SanitizAI 🛡️⚡

[![PyPI Version](https://img.shields.io/pypi/v/sanitizai.svg?color=blue)](https://pypi.org/project/sanitizai/0.1.0/)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://pypi.org/project/sanitizai/0.1.0/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/sanitizai/sanitizai/blob/main/LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20(pure%20standard%20lib)-brightgreen)](#)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#)

> **Lightning-fast, zero-overhead, 100% local text sanitization engine for LLM prompts, application logs, and data storage.**

---

## Why SanitizAI?

In modern cloud applications and AI pipelines, raw user prompts, error stack traces, and chat records frequently pass to third-party Large Language Model providers (such as OpenAI, Anthropic, Google Gemini, Groq, Mistral, and Cohere). Without sanitization, this introduces severe privacy and security liabilities:

* **Exposed Developer Keys**: Leaked OpenAI, Anthropic, AWS, or GitHub credentials lead to account takeovers, unauthorized compute spend, and data exfiltration.
* **Compliance Violations**: Sending customer PII (emails, phone numbers, credit card numbers, national IDs) across external APIs violates **GDPR**, **HIPAA**, **SOC 2**, and **PCI-DSS**.
* **Heavy Dependency Bloat**: Traditional NLP and redaction frameworks require gigabytes of PyTorch weights, Spacy language models, and hundreds of transitive dependencies, leading to massive container sizes and slow cold starts.

**SanitizAI solves this with zero external runtime dependencies.** Built purely on Python's optimized native `re` engine, SanitizAI redacts sensitive data in **microseconds** right on your local machine or server.

---

## Core Pillars

/// grid
/* Column 1 */
=== "⚡ Zero-Overhead & Local"
    Runs 100% locally on your machine or container. Zero remote calls, zero telemetry, zero PyTorch weights. Sanitizes text in sub-millisecond speeds (~60,000+ lines/sec).

/* Column 2 */
=== "🛡️ Smart PII Scrubbing"
    Redacts emails, phone numbers (US, India, global), national IDs (**Aadhaar**, **PAN**, **SSN**), and credit cards with **Luhn algorithm validation** to prevent false positives.

/* Column 3 */
=== "🔑 Multi-Provider AI Guard"
    Pre-configured to mask API keys for OpenAI (`sk-`, `sk-proj-`), Google Gemini (`AQ` and `AIza`), Anthropic (`sk-ant-`), Groq (`gsk_`), Cohere (`c_`), Mistral (`m-`), and Vercel AI Gateway (`ai_`).
///

---

## Supported AI Providers at a Glance

| AI Provider | Key Prefix / Starting Pattern | Status |
| :--- | :--- | :---: |
| **OpenAI (ChatGPT)** | `sk-` or `sk-proj-` | ✅ Protected |
| **Google AI Studio (Gemini)** | `AQ` (New) or `AIza` (Legacy) | ✅ Protected |
| **Anthropic (Claude)** | `sk-ant-` | ✅ Protected |
| **Groq Console** | `gsk_` | ✅ Protected |
| **Cohere** | `c_` or `co_` | ✅ Protected |
| **Mistral AI** | `m-` | ✅ Protected |
| **Vercel AI Gateway** | `ai_` | ✅ Protected |
| **Developer Credentials** | GitHub (`ghp_`), AWS (`AKIA...`), Slack, JWT, PEM keys | ✅ Protected |

---

## Performance Comparison

| Redaction Approach | Runtime Dependencies | Cold Start Latency | Throughput (lines/sec) |
| :--- | :---: | :---: | :---: |
| **SanitizAI** | **0 (Pure Standard Library)** | **< 1 ms** | **~60,000+** |
| Heavy NLP / ML Frameworks | PyTorch, Spacy, Transformers (~2.5 GB) | ~1,500 – 4,000 ms | ~800 |

---

## Ready to Get Started?

Jump right into our **[Getting Started Guide](getting-started.md)** to install the package via `pip` and sanitize your first text stream in under 60 seconds!
