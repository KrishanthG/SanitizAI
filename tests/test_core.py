"""
Comprehensive unit test suite for SanitizAI.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Validates PII redaction, secret key masking (including all major AI providers),
custom rules, streaming, edge cases, and CLI functionality.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

import sanitizai
from sanitizai.cli import main as cli_main
from sanitizai.core import (
    SanitizAI,
    _is_luhn_valid,
    clean,
    redact_pii,
    redact_secrets,
)


class TestPIIRedaction:
    """Tests for Personal Identifiable Information (PII) masking."""

    def test_email_redaction(self):
        text = "Contact alice.smith+filter@sub.corp-domain.co.uk or bob@example.com."
        cleaned = redact_pii(text)
        assert cleaned == "Contact [EMAIL_REDACTED] or [EMAIL_REDACTED]."

    def test_phone_numbers(self):
        sample = (
            "Call US (555) 123-4567 or 555-987-6543, "
            "or India +91 98765 43210, or 9876543210."
        )
        cleaned = redact_pii(sample)
        assert "[PHONE_REDACTED]" in cleaned
        assert "555-987-6543" not in cleaned
        assert "9876543210" not in cleaned

    def test_luhn_algorithm_validation(self):
        # Valid Luhn numbers
        assert _is_luhn_valid("4111111111111111") is True
        assert _is_luhn_valid("4532015000000007") is True
        assert _is_luhn_valid("378282246310005") is True  # Amex
        # Invalid Luhn number
        assert _is_luhn_valid("4532015000000000") is False
        assert _is_luhn_valid("1234567890123456") is False

    def test_credit_card_masking(self):
        # Valid card should be redacted
        text = "Payment received on Visa 4111 1111 1111 1111."
        assert redact_pii(text) == "Payment received on Visa [CREDIT_CARD_REDACTED]."

        # Invalid card numbers / order IDs should NOT be redacted
        safe_text = "Order ID 4532 0150 0000 0000 confirmed."
        assert redact_pii(safe_text) == safe_text

    def test_aadhaar_redaction(self):
        text = "Aadhaar number is 2345 6789 0123 or 9876-5432-1098."
        cleaned = redact_pii(text)
        assert cleaned == "Aadhaar number is [AADHAAR_REDACTED] or [AADHAAR_REDACTED]."

    def test_pan_card_redaction(self):
        text = "Taxpayer PAN is ABCDE1234F for filing."
        cleaned = redact_pii(text)
        assert cleaned == "Taxpayer PAN is [PAN_REDACTED] for filing."

    def test_ssn_redaction(self):
        text = "Social security: 123-45-6789."
        cleaned = redact_pii(text)
        assert cleaned == "Social security: [SSN_REDACTED]."

        # Invalid SSN prefix (000 or 666) should not be redacted
        invalid = "Code 000-45-6789 is invalid."
        assert redact_pii(invalid) == invalid

    def test_ipv4_redaction(self):
        text = "Server hosted at 192.168.1.100 and dns at 8.8.8.8."
        cleaned = redact_pii(text)
        assert cleaned == "Server hosted at [IP_ADDRESS_REDACTED] and dns at [IP_ADDRESS_REDACTED]."


class TestSecretsRedaction:
    """Tests for API keys, tokens, and developer credentials."""

    def test_openai_and_groq_keys(self):
        sample = (
            "OpenAI legacy: sk-1234567890abcdef1234567890\n"
            "OpenAI project: sk-proj-1234567890abcdef1234567890abcdef1234567890\n"
            "Groq key: gsk_1234567890abcdef1234567890abcdef12345678"
        )
        cleaned = redact_secrets(sample)
        assert "sk-1234567890" not in cleaned
        assert "sk-proj-" not in cleaned
        assert "gsk_" not in cleaned
        assert cleaned.count("[SECRET_KEY_REDACTED]") == 3

    def test_all_ai_providers(self):
        # Explicit test for all 7 AI Provider formats:
        # OpenAI (sk- / sk-proj-), Google Gemini (AQ / AIza), Anthropic (sk-ant-),
        # Groq (gsk_), Cohere (c_), Mistral (m-), Vercel AI Gateway (ai_)
        prompt = (
            "OpenAI traditional: sk-1234567890abcdef1234567890\n"
            "OpenAI project: sk-proj-1234567890abcdef1234567890abcdef1234567890\n"
            "Google Gemini New: AQ1234567890abcdef1234567890abcdef\n"
            "Google Gemini Legacy: AIzaSyD-1234567890abcdefghijk-123456789\n"
            "Anthropic Claude: sk-ant-1234567890abcdef1234567890\n"
            "Groq Console: gsk_1234567890abcdef1234567890abcdef12345678\n"
            "Cohere: c_1234567890abcdef1234567890abcdef\n"
            "Mistral AI: m-1234567890abcdef1234567890abcdef\n"
            "Vercel AI Gateway: ai_1234567890abcdef1234567890abcdef"
        )
        cleaned = redact_secrets(prompt)
        assert "sk-1234567890" not in cleaned
        assert "sk-proj-" not in cleaned
        assert "AQ1234567890" not in cleaned
        assert "AIzaSy" not in cleaned
        assert "sk-ant-" not in cleaned
        assert "gsk_" not in cleaned
        assert "c_1234567890" not in cleaned
        assert "m-1234567890" not in cleaned
        assert "ai_1234567890" not in cleaned
        assert cleaned.count("[SECRET_KEY_REDACTED]") == 9

    def test_ai_provider_variable_assignments(self):
        code = (
            'gemini_api_key = "AQ1234567890abcdef1234567890abcdef"\n'
            'mistral_key = "m-abcdef1234567890abcdef1234567890"\n'
            'cohere_api_key = "c_abcdef1234567890abcdef1234567890"\n'
            'openai_api_key = "sk-abcdef1234567890abcdef1234567890"'
        )
        cleaned = redact_secrets(code)
        assert 'gemini_api_key = "[SECRET_KEY_REDACTED]"' in cleaned
        assert 'mistral_key = "[SECRET_KEY_REDACTED]"' in cleaned
        assert 'cohere_api_key = "[SECRET_KEY_REDACTED]"' in cleaned
        assert 'openai_api_key = "[SECRET_KEY_REDACTED]"' in cleaned

    def test_github_tokens(self):
        pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
        text = f"git clone https://{pat}@github.com/repo.git"
        cleaned = redact_secrets(text)
        assert cleaned == "git clone https://[SECRET_KEY_REDACTED]@github.com/repo.git"

        fine_grained = "github_pat_11AAAAAAA0123456789012_abcdefghijklmnopqrstuvwxyz012345678901234567890123456789"
        assert redact_secrets(fine_grained) == "[SECRET_KEY_REDACTED]"

    def test_aws_credentials(self):
        sample = (
            "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        )
        cleaned = redact_secrets(sample)
        assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
        assert "wJalrXUtnFEMI" not in cleaned
        assert "AWS_ACCESS_KEY_ID = [SECRET_KEY_REDACTED]" in cleaned
        assert "aws_secret_access_key = '[SECRET_KEY_REDACTED]'" in cleaned

    def test_generic_assignments_and_bearer(self):
        sample = (
            'api_key = "superSecretKey123456789"\n'
            'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token.signature'
        )
        cleaned = redact_secrets(sample)
        assert "superSecretKey123456789" not in cleaned
        assert 'api_key = "[SECRET_KEY_REDACTED]"' in cleaned
        assert "Authorization: Bearer [SECRET_KEY_REDACTED]" in cleaned

    def test_pem_private_key(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Yt...sample...key...content...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        cleaned = redact_secrets(f"My cert:\n{pem}\nEnd cert.")
        assert pem not in cleaned
        assert "[SECRET_KEY_REDACTED]" in cleaned

    def test_slack_tokens(self):
        text = "Slack: xoxb-123456789012-1234567890123-abcdef123456"
        cleaned = redact_secrets(text)
        assert "xoxb-" not in cleaned
        assert "[SECRET_KEY_REDACTED]" in cleaned


class TestCustomRulesAndBlacklist:
    """Tests for custom regex patterns and word blacklists."""

    def test_custom_regex_pattern(self):
        custom_patterns = {
            r"TICKET-[0-9]+": "[INTERNAL_TICKET]",
            r"ORDER#\d+": "[ORDER_REDACTED]",
        }
        text = "Check TICKET-98234 and ORDER#8821 for details."
        cleaned = clean(text, custom_patterns=custom_patterns)
        assert cleaned == "Check [INTERNAL_TICKET] and [ORDER_REDACTED] for details."

    def test_blacklist_words(self):
        blacklist = ["ProjectTitan", "AcmeCorp Internal", "Confidential"]
        text = "Welcome to ProjectTitan by AcmeCorp Internal! This is Confidential."
        cleaned = clean(text, blacklist_words=blacklist)
        assert "ProjectTitan" not in cleaned
        assert "AcmeCorp Internal" not in cleaned
        assert "Confidential" not in cleaned
        assert cleaned.count("[CONFIDENTIAL_REDACTED]") == 3

    def test_blacklist_custom_replacement(self):
        blacklist = ["SecretSauce"]
        text = "Our recipe contains SecretSauce."
        cleaned = clean(
            text,
            blacklist_words=blacklist,
            blacklist_replacement="[CLASSIFIED]",
        )
        assert cleaned == "Our recipe contains [CLASSIFIED]."


class TestStreamingAndAnalysis:
    """Tests for streaming generator and analysis stats."""

    def test_clean_stream(self):
        lines = [
            "Line 1: contact user@test.com\n",
            "Line 2: server at 10.0.0.1\n",
            "Line 3: clean log line\n",
        ]
        sanitizer = SanitizAI()
        stream_results = list(sanitizer.clean_stream(lines))
        assert len(stream_results) == 3
        assert "[EMAIL_REDACTED]" in stream_results[0]
        assert "[IP_ADDRESS_REDACTED]" in stream_results[1]
        assert stream_results[2] == "Line 3: clean log line\n"

    def test_analyze_functionality(self):
        text = (
            "Email: dev@domain.com, "
            "Server: 192.168.0.1, "
            "OpenAI: sk-1234567890abcdef1234567890, "
            "Gemini: AQ1234567890abcdef1234567890abcdef, "
            "Mistral: m-1234567890abcdef1234567890abcdef."
        )
        sanitizer = SanitizAI()
        stats = sanitizer.analyze(text)
        assert stats.get("email") == 1
        assert stats.get("ipv4") == 1
        assert stats.get("openai_key") == 1
        assert stats.get("gemini_key") == 1
        assert stats.get("mistral_key") == 1


class TestEdgeCasesAndIdempotence:
    """Tests edge cases, empty strings, and idempotency."""

    def test_empty_string(self):
        assert clean("") == ""
        assert redact_pii("") == ""
        assert redact_secrets("") == ""

    def test_idempotence(self):
        text = "Contact john@company.com with key sk-1234567890abcdef1234567890."
        first_pass = clean(text)
        second_pass = clean(first_pass)
        assert first_pass == second_pass
        assert second_pass == "Contact [EMAIL_REDACTED] with key [SECRET_KEY_REDACTED]."

    def test_all_in_one_prompt(self):
        prompt = (
            "System prompt for customer Alice (email: alice@bank.com, phone: 9876543210, "
            "SSN: 123-45-6789, PAN: ABCDE1234F). Connect to 10.0.0.1 using "
            "sk-1234567890abcdef1234567890 and git token ghp_1234567890abcdefghijklmnopqrstuvwxyzAB. "
            "Also backup Gemini key AQ1234567890abcdef1234567890abcdef."
        )
        cleaned = clean(prompt)
        assert "alice@bank.com" not in cleaned
        assert "9876543210" not in cleaned
        assert "123-45-6789" not in cleaned
        assert "ABCDE1234F" not in cleaned
        assert "10.0.0.1" not in cleaned
        assert "sk-1234567890" not in cleaned
        assert "ghp_1234567890" not in cleaned
        assert "AQ1234567890" not in cleaned
        assert "[EMAIL_REDACTED]" in cleaned
        assert "[PHONE_REDACTED]" in cleaned
        assert "[SSN_REDACTED]" in cleaned
        assert "[PAN_REDACTED]" in cleaned
        assert "[IP_ADDRESS_REDACTED]" in cleaned
        assert cleaned.count("[SECRET_KEY_REDACTED]") == 3


class TestCLIInterface:
    """Tests for the SanitizAI command-line interface."""

    def test_cli_direct_text(self, capsys):
        exit_code = cli_main(["Send invoice to user@example.com"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Send invoice to [EMAIL_REDACTED]" in captured.out

    def test_cli_stats_flag(self, capsys):
        exit_code = cli_main(["--stats", "Email dev@test.com with sk-1234567890abcdef1234567890 and AQ1234567890abcdef1234567890abcdef"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[EMAIL_REDACTED]" in captured.out
        assert "SanitizAI Redaction Summary" in captured.err
        assert "email: 1" in captured.err
        assert "openai_key: 1" in captured.err
        assert "gemini_key: 1" in captured.err

    def test_cli_file_in_out(self, tmp_path: Path):
        input_file = tmp_path / "raw.txt"
        output_file = tmp_path / "cleaned.txt"
        input_file.write_text("API key: sk-1234567890abcdef1234567890\nGemini: AQ1234567890abcdef1234567890abcdef\nEmail: a@b.com", encoding="utf-8")

        exit_code = cli_main(["-i", str(input_file), "-o", str(output_file)])
        assert exit_code == 0
        assert output_file.exists()
        cleaned_content = output_file.read_text(encoding="utf-8")
        assert cleaned_content.count("[SECRET_KEY_REDACTED]") == 2
        assert "[EMAIL_REDACTED]" in cleaned_content
        assert "sk-1234567890" not in cleaned_content
        assert "AQ1234567890" not in cleaned_content

    def test_cli_version(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert sanitizai.__version__ in captured.out
