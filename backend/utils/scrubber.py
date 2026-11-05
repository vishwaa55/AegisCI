"""
Secret Scrubber utility for AegisCI.
Ensures sensitive tokens, API keys, passwords, and secrets are stripped from logs
before being stored in the database or passed to LLM prompts.
"""

import re
from typing import Dict, List, Pattern

# Common credential patterns
SECRET_PATTERNS: List[Pattern] = [
    # GitHub Tokens
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}"),
    # OpenAI API Keys
    re.compile(r"sk-[A-Za-z0-9-_]{20,64}"),
    # Anthropic API Keys
    re.compile(r"sk-ant-[A-Za-z0-9-_]{20,64}"),
    # Groq API Keys
    re.compile(r"gsk_[A-Za-z0-9]{40,64}"),
    # Generic Bearer Tokens
    re.compile(r"Bearer\s+[A-Za-z0-9\-_\.=]{20,}", re.IGNORECASE),
    # AWS Access Keys
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Generic Key/Secret assignments (e.g. PASSWORD=..., API_KEY=...)
    re.compile(r'(?i)(password|passwd|secret|token|api_key|apikey|private_key)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?'),
]


def scrub_secrets(text: str) -> str:
    """
    Scrub sensitive credentials, tokens, and secrets from raw logs and text.
    Replaces matched tokens with '[REDACTED_SECRET]'.
    """
    if not text:
        return ""

    scrubbed = text
    for pattern in SECRET_PATTERNS:
        # Check if the pattern has capture groups (like key=value)
        if pattern.groups > 0:
            def replace_val(m):
                full = m.group(0)
                val = m.group(m.lastindex)
                return full.replace(val, "[REDACTED_SECRET]")
            scrubbed = pattern.sub(replace_val, scrubbed)
        else:
            scrubbed = pattern.sub("[REDACTED_SECRET]", scrubbed)

    return scrubbed
