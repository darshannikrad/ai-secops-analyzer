"""Phase 3 — LLM client for the Agentic AI analyst.

Provider resolution (``provider: auto``):
  1. ``OPENAI_API_KEY`` set        -> OpenAI / OpenAI-compatible endpoint
  2. ``OLLAMA`` reachable          -> Ollama local models (OpenAI-compatible)
  3. otherwise                     -> deterministic offline classifier (zero cost)

JSON guardrails: the analyst always asks for strict JSON; malformed replies are
retried once with the parse error fed back, then the offline fallback is used.
Costs are estimated from token counts and configurable per-1M-token prices.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from typing import Any, Dict, List, Optional

from .utils import LOG


class LLMClient:
    """Thin OpenAI-compatible client with robust JSON extraction."""

    def __init__(
        self,
        provider: str = "auto",
        model: str = "gpt-4o-mini",
        base_url: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 900,
        prices: tuple = (0.15, 0.60),
        json_retries: int = 2,
    ):
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.prices = prices
        self.json_retries = json_retries
        self.cost_usd = 0.0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.provider = self._resolve(provider)
        self._client: Any = None
        if self.provider in ("openai", "ollama"):
            self._client = self._build_client()

    # ------------------------------------------------------------------ resolve
    def _resolve(self, provider: str) -> str:
        if provider != "auto":
            return provider
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        try:
            probe = urllib.request.urlopen(
                "http://localhost:11434/v1/models", timeout=1.5
            )
            probe.read()
            return "ollama"
        except Exception:
            return "offline"

    def _build_client(self) -> Any:
        try:
            from openai import OpenAI  # type: ignore
        except ImportError:
            LOG.warning("openai package not installed — using offline classifier")
            self.provider = "offline"
            return None
        kwargs: Dict[str, Any] = {}
        if os.environ.get("OPENAI_API_KEY"):
            kwargs["api_key"] = os.environ["OPENAI_API_KEY"]
        else:
            kwargs["api_key"] = "ollama"  # dummy; local servers ignore it
        url = os.environ.get("OPENAI_BASE_URL") or self.base_url
        if url:
            kwargs["base_url"] = url
        try:
            return OpenAI(**kwargs)
        except Exception as exc:  # pragma: no cover - defensive
            LOG.warning("Could not init OpenAI client (%s) — using offline", exc)
            self.provider = "offline"
            return None

    # ------------------------------------------------------------------ public
    def is_offline(self) -> bool:
        return self.provider == "offline"

    def chat_json(
        self,
        system: str,
        user: str,
        schema_keys: List[str],
    ) -> Dict[str, Any]:
        """Chat completion that guarantees a JSON object back (or raises)."""
        if self._client is None:
            raise RuntimeError("no LLM client available")

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        last_err = ""
        for attempt in range(self.json_retries + 1):
            if attempt:
                messages = messages[:2] + [{
                    "role": "user",
                    "content": f"Your previous reply was not valid JSON. Error: "
                               f"{last_err}. Reply again with ONLY the JSON object.",
                }]
            content, usage = self._complete(messages)
            self.prompt_tokens += usage.get("prompt_tokens", 0)
            self.completion_tokens += usage.get("completion_tokens", 0)
            self.cost_usd = (
                self.prompt_tokens / 1e6 * self.prices[0]
                + self.completion_tokens / 1e6 * self.prices[1]
            )
            try:
                obj = self._extract_json(content)
                missing = [k for k in schema_keys if k not in obj]
                if missing:
                    raise ValueError(f"missing keys: {missing}")
                return obj
            except Exception as exc:
                last_err = str(exc)
        raise ValueError(f"LLM did not return valid JSON after retries: {last_err}")

    # ------------------------------------------------------------------ internals
    def _complete(self, messages: List[Dict[str, str]]) -> tuple:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            response_format={"type": "json_object"},
        )
        return resp.choices[0].message.content, {
            "prompt_tokens": resp.usage.prompt_tokens,
            "completion_tokens": resp.usage.completion_tokens,
        }

    @staticmethod
    def _extract_json(text: str) -> Dict[str, Any]:
        text = text.strip()
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # fall back to first {...} block
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if not match:
                raise
            return json.loads(match.group(0))

    def estimate_tokens(self, *texts: str) -> int:
        return sum(len(t) // 4 for t in texts)


def make_llm_client(settings) -> LLMClient:
    from .config import Settings

    if isinstance(settings, Settings):
        s = settings
        return LLMClient(
            provider=s.llm_provider, model=s.llm_model, base_url=s.llm_base_url,
            temperature=s.llm_temperature, max_tokens=s.llm_max_tokens,
            prices=s.llm_prices, json_retries=s.llm_json_retries,
        )
    return LLMClient()
