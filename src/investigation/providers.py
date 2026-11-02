"""LLM provider abstractions for AI-assisted security investigations."""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..utils.config import get_settings

logger = logging.getLogger(__name__)

# Fallback check for httpx
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None  # type: ignore
    HTTPX_AVAILABLE = False


class LLMProvider(ABC):
    """Abstract base class for Large Language Model providers."""

    provider_name: str = "base"

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2000,
    ) -> str:
        """Generate a response text from the LLM model.

        Args:
            system_prompt: System directive instructions.
            user_prompt: User prompt content containing task context.
            max_tokens: Maximum tokens in generated completion.

        Returns:
            Generated text string response.
        """
        pass

    def parse_tool_calls(self, response: str) -> List[Dict[str, Any]]:
        """Parse structured tool calls from an LLM response.

        Extracts tool calls formatted as JSON arrays, markdown code fences,
        or line-delimited `TOOL_CALL: <name> <json_args>` statements.

        Args:
            response: Raw textual response string from LLM.

        Returns:
            List of dictionaries with keys: 'tool_name', 'tool_args', 'reasoning'.
        """
        tool_calls: List[Dict[str, Any]] = []
        if not response or not response.strip():
            return tool_calls

        # Strategy 1: Look for JSON fences (```json ... ```)
        json_fence_matches = re.findall(
            r"```(?:json)?\s*([\s\S]*?)\s*```", response, re.IGNORECASE
        )
        for block in json_fence_matches:
            block = block.strip()
            try:
                parsed = json.loads(block)
                extracted = self._extract_tool_calls_from_obj(parsed)
                if extracted:
                    tool_calls.extend(extracted)
            except (json.JSONDecodeError, ValueError):
                pass

        if tool_calls:
            return tool_calls

        # Strategy 2: Attempt parsing the entire response as direct JSON
        trimmed = response.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (
            trimmed.startswith("[") and trimmed.endswith("]")
        ):
            try:
                parsed = json.loads(trimmed)
                extracted = self._extract_tool_calls_from_obj(parsed)
                if extracted:
                    return extracted
            except (json.JSONDecodeError, ValueError):
                pass

        # Strategy 3: Regex pattern matching for TOOL_CALL: <tool_name> <json_args>
        pattern = re.compile(
            r"TOOL_CALL:\s*([a-zA-Z0-9_]+)\s*(\{[^\n\r]*\})", re.IGNORECASE
        )
        for match in pattern.finditer(response):
            tool_name = match.group(1).strip()
            args_str = match.group(2).strip()
            try:
                args = json.loads(args_str)
                tool_calls.append(
                    {
                        "tool_name": tool_name,
                        "tool_args": args if isinstance(args, dict) else {},
                        "reasoning": "Extracted from inline TOOL_CALL annotation",
                    }
                )
            except json.JSONDecodeError:
                pass

        return tool_calls

    def _extract_tool_calls_from_obj(self, obj: Any) -> List[Dict[str, Any]]:
        """Extract tool call dictionaries from parsed Python data structures."""
        results: List[Dict[str, Any]] = []

        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    extracted = self._dict_to_tool_call(item)
                    if extracted:
                        results.append(extracted)
            return results

        if isinstance(obj, dict):
            # Check for keys like 'tool_calls', 'calls', 'tools'
            if "tool_calls" in obj and isinstance(obj["tool_calls"], list):
                for item in obj["tool_calls"]:
                    if isinstance(item, dict):
                        extracted = self._dict_to_tool_call(item)
                        if extracted:
                            results.append(extracted)
                return results

            # Single tool call object
            extracted = self._dict_to_tool_call(obj)
            if extracted:
                results.append(extracted)

        return results

    def _dict_to_tool_call(self, d: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize a dictionary into a validated tool call schema."""
        name = d.get("tool_name") or d.get("tool") or d.get("name")
        if not name or not isinstance(name, str):
            return None

        args = (
            d.get("tool_args")
            or d.get("args")
            or d.get("arguments")
            or d.get("parameters")
            or {}
        )
        if not isinstance(args, dict):
            args = {}

        reasoning = d.get("reasoning") or d.get("thought") or ""
        return {
            "tool_name": str(name).strip(),
            "tool_args": args,
            "reasoning": str(reasoning).strip(),
        }


class OfflineProvider(LLMProvider):
    """Offline heuristic provider. Bypasses external network calls."""

    provider_name = "offline"

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2000,
    ) -> str:
        """Return empty string; investigation is handled deterministically by agent logic."""
        return ""


class OpenAIProvider(LLMProvider):
    """OpenAI API integration for agentic investigations."""

    provider_name = "openai"

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o") -> None:
        """Initialize OpenAI provider with API credentials and model configuration."""
        settings = get_settings()
        self.api_key = api_key or settings.openai_api_key
        self.model = model

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2000,
    ) -> str:
        """Generate response via OpenAI Chat Completions API."""
        if not self.api_key:
            logger.warning("OpenAI API key not provided; returning provider error fallback.")
            return f"[{self.provider_name} error: Missing OPENAI_API_KEY]"

        if not HTTPX_AVAILABLE:
            return f"[{self.provider_name} error: httpx client library is not available]"

        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }

        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return str(content or "")
        except Exception as exc:
            logger.error(f"OpenAI API call failed: {exc}")
            return f"[{self.provider_name} error: {exc}]"


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API integration for agentic investigations."""

    provider_name = "anthropic"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-3-5-sonnet-20241022",
    ) -> None:
        """Initialize Anthropic provider with API credentials and model name."""
        settings = get_settings()
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2000,
    ) -> str:
        """Generate response via Anthropic Messages API."""
        if not self.api_key:
            logger.warning("Anthropic API key not provided; returning provider error fallback.")
            return f"[{self.provider_name} error: Missing ANTHROPIC_API_KEY]"

        if not HTTPX_AVAILABLE:
            return f"[{self.provider_name} error: httpx client library is not available]"

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }

        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content_blocks = data.get("content", [])
                texts = [
                    b.get("text", "")
                    for b in content_blocks
                    if isinstance(b, dict) and b.get("type") == "text"
                ]
                return "\n".join(texts)
        except Exception as exc:
            logger.error(f"Anthropic API call failed: {exc}")
            return f"[{self.provider_name} error: {exc}]"


class GoogleProvider(LLMProvider):
    """Google Gemini API integration for agentic investigations."""

    provider_name = "google"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-1.5-pro",
    ) -> None:
        """Initialize Google provider with API credentials and model name."""
        settings = get_settings()
        self.api_key = api_key or settings.google_api_key
        self.model = model

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2000,
    ) -> str:
        """Generate response via Google Gemini REST endpoint."""
        if not self.api_key:
            logger.warning("Google API key not provided; returning provider error fallback.")
            return f"[{self.provider_name} error: Missing GOOGLE_API_KEY]"

        if not HTTPX_AVAILABLE:
            return f"[{self.provider_name} error: httpx client library is not available]"

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        headers = {"Content-Type": "application/json"}
        full_content = f"{system_prompt}\n\nTask Context:\n{user_prompt}"
        payload = {
            "contents": [{"parts": [{"text": full_content}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.2,
            },
        }

        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = (
                        candidates[0]
                        .get("content", {})
                        .get("parts", [])
                    )
                    return "".join([p.get("text", "") for p in parts])
                return ""
        except Exception as exc:
            logger.error(f"Google Gemini API call failed: {exc}")
            return f"[{self.provider_name} error: {exc}]"


class LocalProvider(LLMProvider):
    """Local LLM endpoint integration (e.g. Ollama or vLLM)."""

    provider_name = "local"

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        """Initialize local inference endpoint."""
        settings = get_settings()
        self.endpoint_url = endpoint_url or settings.local_llm_url
        self.model = model or settings.local_llm_model

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2000,
    ) -> str:
        """Send completion request to local LLM server."""
        if not HTTPX_AVAILABLE:
            return f"[{self.provider_name} error: httpx client library is not available]"

        payload = {
            "model": self.model,
            "prompt": f"{system_prompt}\n\n{user_prompt}",
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.2,
            },
        }

        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(self.endpoint_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return str(data.get("response", ""))
        except Exception as exc:
            logger.error(f"Local LLM call to {self.endpoint_url} failed: {exc}")
            return f"[{self.provider_name} error: {exc}]"


def get_provider(provider_name: str) -> LLMProvider:
    """Factory function to resolve an LLMProvider instance by name.

    Args:
        provider_name: Provider identifier (e.g., 'offline', 'openai', 'anthropic', 'google', 'local').

    Returns:
        Configured LLMProvider instance.
    """
    normalized = str(provider_name or "").strip().lower()
    if normalized == "openai":
        return OpenAIProvider()
    elif normalized in ("anthropic", "claude"):
        return AnthropicProvider()
    elif normalized in ("google", "gemini"):
        return GoogleProvider()
    elif normalized in ("local", "ollama"):
        return LocalProvider()
    elif normalized == "offline":
        return OfflineProvider()
    else:
        logger.info(f"Unrecognized provider '{provider_name}'; falling back to OfflineProvider.")
        return OfflineProvider()
