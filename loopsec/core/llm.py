"""
LoopSec LLM Client

Thin wrapper around LiteLLM for provider-agnostic LLM calls.
Supports OpenAI, Anthropic, and any LiteLLM-compatible provider.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import litellm
from litellm import completion

from loopsec.core.config import get_config

logger = logging.getLogger(__name__)

# Suppress litellm noise
litellm.suppress_debug_info = True


class LLMClient:
    """Provider-agnostic LLM client."""

    def __init__(self, model: str | None = None, temperature: float | None = None):
        cfg = get_config().llm
        self.model = model or cfg.model
        self.temperature = temperature if temperature is not None else cfg.temperature
        self.max_tokens = cfg.max_tokens
        self.timeout = cfg.timeout

    def chat(
        self,
        prompt: str,
        system: str = "",
        history: list[dict[str, str]] | None = None,
    ) -> str:
        """Send a chat completion request and return the text response."""
        messages: list[dict[str, str]] = []

        if system:
            messages.append({"role": "system", "content": system})

        if history:
            messages.extend(history)

        messages.append({"role": "user", "content": prompt})

        logger.debug(f"LLM request: model={self.model}, messages={len(messages)}")

        response = completion(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            timeout=self.timeout,
        )

        text = response.choices[0].message.content or ""
        logger.debug(f"LLM response: {len(text)} chars")
        return text

    def chat_json(
        self,
        prompt: str,
        system: str = "",
        history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Chat expecting a JSON response. Parses and returns dict."""
        system_with_json = (
            f"{system}\n\nIMPORTANT: Respond ONLY with valid JSON. "
            "No markdown, no backticks, no explanation outside the JSON."
        )

        raw = self.chat(prompt, system=system_with_json, history=history)

        # Strip common markdown wrapping
        cleaned = raw.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {e}\nRaw: {raw[:500]}")
            return {"error": "Failed to parse JSON", "raw": raw[:1000]}


# Convenience singleton
_client: LLMClient | None = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
