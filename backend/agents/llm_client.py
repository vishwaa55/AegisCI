import json
import os
import re
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()


class LLMClient:
    """
    Unified LLM Client supporting Groq, OpenAI, and Anthropic.
    Optimized for Groq with fast structured output and patch generation.
    """

    def __init__(self):
        self.provider = os.getenv("DEFAULT_LLM_PROVIDER", "groq").lower()
        self.groq_api_key = os.getenv("GROQ_API_KEY", "")
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")

        # Models
        self.groq_model = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")

        self._init_clients()

    def _init_clients(self):
        self._groq_client = None
        self._openai_client = None
        self._anthropic_client = None

        if self.groq_api_key:
            try:
                from groq import Groq
                self._groq_client = Groq(api_key=self.groq_api_key)
            except Exception as e:
                print(f"[LLMClient] Warning: Failed to initialize Groq client: {e}")

        if self.openai_api_key:
            try:
                from openai import OpenAI
                self._openai_client = OpenAI(api_key=self.openai_api_key)
            except Exception as e:
                print(f"[LLMClient] Warning: Failed to initialize OpenAI client: {e}")

        if self.anthropic_api_key:
            try:
                from anthropic import Anthropic
                self._anthropic_client = Anthropic(api_key=self.anthropic_api_key)
            except Exception as e:
                print(f"[LLMClient] Warning: Failed to initialize Anthropic client: {e}")

    def generate_text(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        """Generate text using the configured provider with automatic rate limit backoff."""
        import time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if self.provider == "groq" and self._groq_client:
                    res = self._groq_client.chat.completions.create(
                        model=self.groq_model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=temperature,
                    )
                    return res.choices[0].message.content or ""

                elif self.provider == "openai" and self._openai_client:
                    res = self._openai_client.chat.completions.create(
                        model=self.openai_model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=temperature,
                    )
                    return res.choices[0].message.content or ""

                elif self.provider == "anthropic" and self._anthropic_client:
                    res = self._anthropic_client.messages.create(
                        model=self.anthropic_model,
                        max_tokens=4096,
                        system=system_prompt,
                        messages=[{"role": "user", "content": user_prompt}],
                        temperature=temperature,
                    )
                    return res.content[0].text or ""

                # Fallback if primary is missing or failing: try any available client
                if self._groq_client:
                    res = self._groq_client.chat.completions.create(
                        model=self.groq_model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=temperature,
                    )
                    return res.choices[0].message.content or ""

                raise RuntimeError("No LLM provider client is configured with an active API key.")
            except Exception as e:
                err_str = str(e).lower()
                if ("429" in err_str or "rate limit" in err_str or "tokens per minute" in err_str) and attempt < max_retries - 1:
                    time.sleep(6.0 * (attempt + 1))
                    continue
                raise

    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """Generate structured JSON object using the configured provider with automatic rate limit backoff."""
        import time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if self.provider == "groq" and self._groq_client:
                    res = self._groq_client.chat.completions.create(
                        model=self.groq_model,
                        response_format={"type": "json_object"},
                        messages=[
                            {"role": "system", "content": system_prompt + "\nYou MUST return valid JSON."},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=0.1,
                    )
                    raw = res.choices[0].message.content or "{}"
                    return self._parse_json(raw)

                elif self.provider == "openai" and self._openai_client:
                    res = self._openai_client.chat.completions.create(
                        model=self.openai_model,
                        response_format={"type": "json_object"},
                        messages=[
                            {"role": "system", "content": system_prompt + "\nYou MUST return valid JSON."},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=0.1,
                    )
                    raw = res.choices[0].message.content or "{}"
                    return self._parse_json(raw)

                # Fallback: prompt to return json and parse
                text = self.generate_text(system_prompt + "\nReturn ONLY valid JSON format with no markdown wrappers.", user_prompt, temperature=0.1)
                return self._parse_json(text)
            except Exception as e:
                err_str = str(e).lower()
                if ("429" in err_str or "rate limit" in err_str or "tokens per minute" in err_str) and attempt < max_retries - 1:
                    time.sleep(6.0 * (attempt + 1))
                    continue
                raise

    def _parse_json(self, text: str) -> Dict[str, Any]:
        """Extract and parse JSON from LLM output even if surrounded by markdown code fences."""
        cleaned = text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Try regex to locate first { and last }
            match = re.search(r'\{.*\}', cleaned, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except Exception:
                    pass
            return {"error": "Failed to parse JSON", "raw": text}
