import sanitizai

sample_prompt = """
=== Multi-Provider AI Credentials Prompt ===
OpenAI (ChatGPT): sk-proj-9876543210abcdef9876543210abcdef
Google Gemini (New AQ Key): AQ1234567890abcdef1234567890abcdef
Google Gemini (Legacy AIza): AIzaSyD-1234567890abcdefghijk-123456789
Anthropic (Claude): sk-ant-api03-1234567890abcdef1234567890
Groq Console: gsk_1234567890abcdef1234567890abcdef12345678
Cohere: c_1234567890abcdef1234567890abcdef
Mistral AI: m-1234567890abcdef1234567890abcdef
Vercel AI Gateway: ai_1234567890abcdef1234567890abcdef
Customer Support Contact: alex@company.com (Phone: +1 555-019-2834)
"""

print("--- Original Text ---")
print(sample_prompt)

print("--- Sanitized by SanitizAI ---")
print(sanitizai.clean(sample_prompt))