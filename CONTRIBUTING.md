# Contributing to SanitizAI 🛠️

First off, thank you for considering contributing to **SanitizAI**! We welcome bug fixes, regex enhancements, test cases, and performance optimizations from developers and security practitioners worldwide.

---

## The Golden Rule: Zero External Runtime Dependencies

> [!IMPORTANT]
> **SanitizAI is strictly zero-overhead and 100% dependency-free at runtime.**
> We do NOT accept pull requests that introduce external runtime dependencies (such as heavy NLP libraries, ML models, or third-party regex wrappers). All core redaction must run purely on the Python standard library (`re`, `dataclasses`, `typing`, `sys`, `pathlib`).

---

## Development Environment Setup

### 1. Prerequisites
* Python **3.10** or newer.
* `git` installed and configured.

### 2. Fork & Clone
```bash
# Clone your fork
git clone https://github.com/<your-username>/SanitizAI.git
cd SanitizAI
```

### 3. Create a Virtual Environment
```bash
# Create and activate virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows PowerShell:
.venv\Scripts\Activate.ps1
```

### 4. Install in Editable Mode with Dev Dependencies
```bash
pip install -e ".[dev]"
```

---

## Development Workflow

### Creating a Branch
Create a descriptive feature branch off `main`:
```bash
git checkout -b feat/add-mistral-key-pattern
# or
git checkout -b fix/phone-number-boundary
```

### Adding New Redaction Patterns
When adding a new PII entity or secret key format:

1. **Define Pre-Compiled Pattern in [`sanitizai/core.py`](sanitizai/core.py)**:
   - Ensure patterns are strict and use non-capturing groups `(?:...)` where possible.
   - Guard against ReDoS: Avoid overlapping wildcard quantifiers like `(.*)*`.
2. **Register the Pattern in `SanitizAI._build_rules()`**:
   - Assign appropriate `category` (`"pii"`, `"secrets"`, or `"custom"`).
   - Use standard replacement placeholders: `[SECRET_KEY_REDACTED]`, `[EMAIL_REDACTED]`, etc.
3. **Add Comprehensive Tests in [`tests/test_core.py`](tests/test_core.py)**:
   - Include positive test cases (valid tokens masked).
   - Include negative test cases (ordinary text and safe strings preserved).
   - Include edge cases (empty strings, idempotency, streaming).

---

## Running Tests

We require **100% test pass rate** for any accepted contribution:

```bash
# Run the complete pytest test suite:
python -m pytest tests/ -v

# Run tests with coverage reporting (optional):
python -m pytest tests/ --cov=sanitizai
```

---

## Coding Standards & Style

* **Typing**: All functions, methods, and classes must have explicit Python type annotations.
* **Docstrings**: Maintain standard Google/Sphinx style docstrings for all public methods and modules.
* **Formatting**: Follow PEP 8 guidelines (100 character maximum line length recommended).
* **CLI & API Dual Support**: If modifying engine options, ensure both programmatic API (`SanitizAI`, `clean()`) and CLI options (`sanitizai/cli.py`) remain consistent.

---

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

* `feat: add support for new AI provider key format`
* `fix: prevent false positive on 16-digit order identifiers`
* `docs: update quick start instructions in README`
* `test: add unit test for Aadhaar negative lookahead`
* `perf: optimize pre-compiled regex execution order`

---

## Submitting a Pull Request (PR)

1. Ensure all existing and new tests pass locally: `python -m pytest tests/ -v`.
2. Push your changes to your fork:
   ```bash
   git push origin feat/your-feature-name
   ```
3. Open a Pull Request against the `main` branch of the upstream repository.
4. Fill out the PR description with:
   - **Summary of Changes**: What was added, fixed, or updated.
   - **Motivation / Context**: Link relevant issue numbers.
   - **Verification**: Output from your local `pytest` run.

---

## Reporting Security Issues

For sensitive security disclosures (such as pattern bypasses or secret leakage), please do **NOT** submit a public pull request or issue. Instead, refer to our [SECURITY.md](SECURITY.md) policy for confidential disclosure procedures or connect with the maintainer directly via LinkedIn: **[krishanth-g](https://www.linkedin.com/in/krishanth-g)**.

---

## Community & Questions

Have questions or want to discuss feature ideas before opening a PR? Feel free to connect directly with the maintainer on LinkedIn: **[krishanth-g](https://www.linkedin.com/in/krishanth-g)**.
