"""LLM client for advanced AI reasoning.
Provides OpenAI-compatible API access with a graceful offline fallback.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


class LLMClient:
    """Small wrapper around OpenAI-compatible APIs and fallback heuristics."""

    def __init__(self, model: Optional[str] = None):
        self.model = model or os.getenv("LLM_MODEL", "gpt-4")
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.base_url = os.getenv("LLM_API_BASE", "https://api.openai.com/v1")

    def chat(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate a response using the configured LLM provider if available."""
        system_prompt = system_prompt or (
            "You are a world-class cybersecurity analyst and AI agent. "
            "Analyze threats, explain risks clearly, and propose secure remediation steps."
        )

        if self.api_key:
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                }
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": float(os.getenv("TEMPERATURE", "0.4")),
                }
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=30,
                )
                response.raise_for_status()
                result = response.json()
                if "choices" in result and result["choices"]:
                    return result["choices"][0]["message"]["content"]
            except Exception as exc:  # pragma: no cover - network or API failures
                logger.warning("LLM API call failed, falling back to local reasoning: %s", exc)

        return self._offline_reasoning(prompt)

    def _offline_reasoning(self, prompt: str) -> str:
        """Fallback reasoning engine that still produces useful security guidance."""
        text = prompt.lower()
        if "sql" in text or "injection" in text:
            return (
                "Detected likely SQL injection risk. Review database query construction and "
                "replace string concatenation with parameterized queries. Ensure input is validated "
                "and never directly interpolated into SQL text."
            )
        if "xss" in text or "script" in text or "innerhtml" in text:
            return (
                "Detected likely cross-site scripting risk. Escape untrusted output before rendering "
                "HTML, avoid unsafe DOM APIs, and sanitize user input before persistence."
            )
        if "secret" in text or "token" in text or "key" in text:
            return (
                "Hardcoded secrets or tokens are dangerous. Move secrets to environment variables or a "
                "vault, rotate exposed credentials immediately, and add secret scanning to CI/CD."
            )
        if "auth" in text or "login" in text:
            return (
                "Authentication issues often come from weak session checks or missing validation. "
                "Verify password hashing, session invalidation, MFA requirements, and lockout controls."
            )

        return (
            "I don't see a specific exploit pattern in the prompt, but this code should still be reviewed for "
            "input validation, unsafe deserialization, secret exposure, dependency vulnerabilities, and "
            "missing authorization checks."
        )
