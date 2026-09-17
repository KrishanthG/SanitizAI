# CLI Guide 💻

SanitizAI provides a standalone command-line executable `sanitizai` for terminal text scrubbing, file processing, and Unix pipeline log filtering.

---

## Overview

When you install SanitizAI via `pip install sanitizai`, the `sanitizai` command becomes immediately available in your terminal:

```bash
sanitizai --help
```

---

## Common Use Cases

### 1. Direct String Redaction
Pass a string argument directly to the terminal utility:

```bash
sanitizai "Contact support@corp.com or use key sk-proj-1234567890abcdef1234567890abcdef"
```

#### Output
```text
Contact [EMAIL_REDACTED] or use key [SECRET_KEY_REDACTED]
```

---

### 2. Unix Pipeline (STDIN / STDOUT)
SanitizAI is designed as a first-class Unix filter. When no string argument or input file is provided, it consumes data from standard input line-by-line:

=== "Cat Pipe"
    ```bash
    cat production.log | sanitizai > sanitized.log
    ```

=== "Streaming Live Logs"
    ```bash
    tail -f /var/log/app.log | sanitizai
    ```

=== "Shell Redirection"
    ```bash
    sanitizai < dirty_prompts.txt > safe_prompts.txt
    ```

---

### 3. File Input & Output Flags
Clean an existing file directly into a new target file:

```bash
sanitizai -i raw_records.txt -o clean_records.txt
```

* If `-o` is omitted, the sanitized output is printed directly to `STDOUT`.

---

### 4. Statistical Debugging (`--stats`)
Use `--stats` to print a structured summary of all detected and redacted entities to `STDERR` while passing sanitized text through `STDOUT`:

```bash
sanitizai --stats "Alice (alice@bank.com) accessed 192.168.1.1 using sk-1234567890abcdef1234567890"
```

#### Output
```text
Alice ([EMAIL_REDACTED]) accessed [IP_ADDRESS_REDACTED] using [SECRET_KEY_REDACTED]

--- SanitizAI Redaction Summary ---
  email: 1
  ipv4: 1
  openai_key: 1
  Total Redactions: 3
-----------------------------------
```

---

### 5. Custom Blacklists
Scrub custom confidential terms or organization codenames on-the-fly using `--blacklist`:

```bash
sanitizai --blacklist "ProjectApollo,TopSecretDeal" "Discussing ProjectApollo with sk-proj-1234567890abcdef1234567890abcdef"
```

#### Output
```text
Discussing [CONFIDENTIAL_REDACTED] with [SECRET_KEY_REDACTED]
```

---

### 6. Selective Redaction Flags
Disable specific redaction categories if only partial sanitization is required:

* `--no-pii`: Skips email, phone, card, Aadhaar, PAN, SSN, and IP masking (only secrets will be scrubbed).
* `--no-secrets`: Skips API key and developer credential masking (only PII will be scrubbed).

```bash
# Scrub secrets, but keep user email visible
sanitizai --no-pii "User dev@test.com used key sk-1234567890abcdef1234567890"
# -> "User dev@test.com used key [SECRET_KEY_REDACTED]"
```

---

## CLI Options Reference

| Option | Flag | Description |
| :--- | :--- | :--- |
| `text` | Positional | Text string to sanitize (omit to read from STDIN or input file) |
| `--input` | `-i` | Path to input file to sanitize |
| `--output` | `-o` | Path to destination output file (defaults to `STDOUT`) |
| `--stats` | | Prints summary of detected and redacted entity counts to `STDERR` |
| `--blacklist` | | Comma-separated list of custom words or phrases to redact |
| `--no-pii` | | Disables PII redaction |
| `--no-secrets` | | Disables API key & credentials redaction |
| `--version` | `-v` | Displays installed program version |
| `--help` | `-h` | Displays usage instructions |
