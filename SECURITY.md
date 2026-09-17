# Security Policy 🛡️

The SanitizAI project is committed to ensuring the highest standards of security, privacy, and responsible vulnerability disclosure. Because SanitizAI is designed to safeguard sensitive Personal Identifiable Information (PII) and high-value developer credentials, the integrity, predictability, and ReDoS-resilience of our core engine are our top priorities.

---

## Supported Versions

Security updates, bug fixes, and critical patches are actively provided for the following versions:

| Version | Supported | Notes |
| :--- | :---: | :--- |
| `0.1.x` | ✅ | Active development & current stable release |
| `< 0.1.0` | ❌ | Pre-release versions (deprecated) |

---

## Threat Model & Security Guarantees

SanitizAI operates on strict zero-trust, privacy-first principles:

1. **100% Local Execution**: All string sanitization and pattern matching occurs strictly within your local Python runtime environment. SanitizAI makes **zero network calls**, sends **zero telemetry**, and communicates with **no external servers**.
2. **Zero Runtime Supply-Chain Dependencies**: SanitizAI does not depend on third-party PyPI packages for core execution. This completely mitigates dependency-confusion, malicious typosquatting, and transitive supply-chain attacks.
3. **ReDoS (Regular Expression Denial of Service) Prevention**: All internal regex patterns are architected and benchmarked to avoid catastrophic polynomial or exponential backtracking ($O(2^n)$ or $O(n^2)$).
4. **Idempotence & Non-Destructive Integrity**: Sanitization guarantees that previously redacted placeholders (e.g. `[EMAIL_REDACTED]`, `[SECRET_KEY_REDACTED]`) are preserved idempotently without infinite redaction loops or text corruption.

---

## Reporting a Vulnerability (Responsible Disclosure)

> [!IMPORTANT]
> **Please do NOT report security vulnerabilities via public GitHub issues, discussions, or pull requests.**

If you believe you have discovered a security vulnerability, pattern bypass, or ReDoS vector in SanitizAI, please follow our responsible disclosure process:

1. **GitHub Private Vulnerability Reporting**:
   - Navigate to the repository's **Security** tab on GitHub and click **"Report a vulnerability"** to submit a private draft advisory.
2. **Maintainer Direct Contact**:
   - Reach out directly to the maintainer via LinkedIn: **[krishanth-g](https://www.linkedin.com/in/krishanth-g)**.

### What to Include in Your Report:
* **Description**: A clear summary of the vulnerability, false negative (secret leak), or ReDoS vector.
* **Proof of Concept (PoC)**: Minimal Python code snippet or sample string reproducing the issue.
* **Impact Assessment**: How this vulnerability affects downstream applications (e.g., prompt leakage to LLMs, log pollution, denial of service).
* **Suggested Fix (Optional)**: If you have identified a regex fix or test case, please share your proposal.

---

## Vulnerability Handling SLA

We are committed to rapid response and resolution:

* **Initial Response**: Within **24 hours** acknowledging receipt of your report.
* **Triage & Validation**: Within **48 hours** confirming reproducible status and severity score (CVSS).
* **Fix & Release**: Within **7 business days** (or sooner for critical severity issues).
* **Public Disclosure**: Coordinated public release of security advisory and CVE assignment once the patch is published.

---

## Safe Harbor & Research Guidelines

We consider security research conducted under the following guidelines to be authorized and protected:
* Research must not intentionally exploit vulnerabilities to degrade public service availability or access unauthorized user data.
* Vulnerabilities must be reported promptly and kept confidential until a coordinated patch is published.
* We will not pursue legal action against security researchers who adhere in good faith to this policy.
