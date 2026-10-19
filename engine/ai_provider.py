"""
Configurable AI Provider Adapter for Digital Time Machine Copilot.
Supports OpenAI official SDK with standard HTTP library fallback.
Enforces strict secret isolation, timeout bounds, and error sanitization.
"""

import os
import json
import urllib.request
import urllib.error
from abc import ABC, abstractmethod


class AIProviderError(Exception):
    """Base exception for AI provider errors."""
    pass


class AIProviderAuthError(AIProviderError):
    """Raised when authentication credentials are missing or invalid."""
    pass


class AIProviderRateLimitError(AIProviderError):
    """Raised when rate limits or quotas are exceeded."""
    pass


class AIProviderTimeoutError(AIProviderError):
    """Raised when the AI provider request times out."""
    pass


class BaseAIProvider(ABC):
    """Abstract base class for all AI provider adapters."""

    @abstractmethod
    def generate_chat_completion(
        self,
        messages: list[dict],
        max_tokens: int = 1024,
        temperature: float = 0.1
    ) -> dict:
        """Generates a chat completion given a list of chat messages."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the provider has all required credentials configured."""
        pass

    @abstractmethod
    def get_status(self) -> dict:
        """Returns provider status metadata without leaking secrets."""
        pass


class OpenAIProvider(BaseAIProvider):
    """
    OpenAI provider adapter.
    Uses official openai SDK if installed, or fallback to standard urllib.request.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        max_tokens: int | None = None
    ):
        self._explicit_api_key = api_key
        self._explicit_model = model
        self._explicit_timeout = timeout
        self._explicit_max_tokens = max_tokens

    @property
    def api_key(self) -> str:
        if self._explicit_api_key is not None:
            return self._explicit_api_key.strip()
        return os.environ.get("OPENAI_API_KEY", "").strip()

    @api_key.setter
    def api_key(self, val: str | None):
        self._explicit_api_key = val

    @property
    def model(self) -> str:
        if self._explicit_model is not None:
            return self._explicit_model.strip()
        return os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip()

    @model.setter
    def model(self, val: str | None):
        self._explicit_model = val

    @property
    def timeout(self) -> int:
        if self._explicit_timeout is not None:
            return self._explicit_timeout
        try:
            return int(os.environ.get("AI_REQUEST_TIMEOUT", "25"))
        except (ValueError, TypeError):
            return 25

    @property
    def max_tokens(self) -> int:
        if self._explicit_max_tokens is not None:
            return self._explicit_max_tokens
        try:
            return int(os.environ.get("AI_MAX_OUTPUT_TOKENS", "1024"))
        except (ValueError, TypeError):
            return 1024

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def get_status(self) -> dict:
        configured = self.is_configured()
        return {
            "provider": "openai",
            "configured": configured,
            "model": self.model,
            "timeout_seconds": self.timeout,
            "status_message": (
                "OpenAI Copilot provider active and ready."
                if configured else
                "AI provider not configured: Set the OPENAI_API_KEY environment variable. "
                "Deterministic forensic features remain fully operational."
            )
        }

    def generate_chat_completion(
        self,
        messages: list[dict],
        max_tokens: int | None = None,
        temperature: float = 0.1
    ) -> dict:
        if not self.is_configured():
            raise AIProviderAuthError(
                "AI provider is not configured. Set the OPENAI_API_KEY environment variable "
                "to enable the Evidence-Grounded AI Copilot."
            )

        tokens_to_use = max_tokens or self.max_tokens

        # Attempt 1: Official OpenAI SDK if installed
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key, timeout=self.timeout)
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=tokens_to_use,
                temperature=temperature
            )
            content = response.choices[0].message.content or ""
            usage = {
                "prompt_tokens": getattr(response.usage, "prompt_tokens", 0) if response.usage else 0,
                "completion_tokens": getattr(response.usage, "completion_tokens", 0) if response.usage else 0,
                "total_tokens": getattr(response.usage, "total_tokens", 0) if response.usage else 0
            }
            return {
                "content": content,
                "model": response.model or self.model,
                "usage": usage,
                "provider": "openai-sdk"
            }
        except ImportError:
            pass  # Fall back to native HTTP client
        except openai.AuthenticationError as ex:
            raise AIProviderAuthError("OpenAI authentication failed: Invalid or expired API credentials.") from ex
        except openai.RateLimitError as ex:
            raise AIProviderRateLimitError("OpenAI rate limit or quota exceeded. Please retry in a moment.") from ex
        except openai.APITimeoutError as ex:
            raise AIProviderTimeoutError(f"OpenAI request timed out after {self.timeout} seconds.") from ex
        except Exception as ex:
            raise AIProviderError(f"OpenAI service error: {str(ex)}") from ex

        # Attempt 2: Standard urllib.request (Zero external dependency fallback)
        return self._http_request_fallback(messages, tokens_to_use, temperature)

    def _http_request_fallback(
        self,
        messages: list[dict],
        max_tokens: int,
        temperature: float
    ) -> dict:
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        data_bytes = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                res_json = json.loads(body)
                choices = res_json.get("choices", [])
                if not choices:
                    raise AIProviderError("OpenAI returned response with no choices.")
                content = choices[0].get("message", {}).get("content", "")
                usage = res_json.get("usage", {})
                return {
                    "content": content,
                    "model": res_json.get("model", self.model),
                    "usage": usage,
                    "provider": "openai-http"
                }
        except urllib.error.HTTPError as ex:
            if ex.code == 401:
                raise AIProviderAuthError("OpenAI authentication failed: Invalid or expired API credentials.") from ex
            elif ex.code == 429:
                raise AIProviderRateLimitError("OpenAI rate limit or quota exceeded. Please retry in a moment.") from ex
            else:
                error_msg = f"HTTP Error {ex.code}: {ex.reason}"
                try:
                    err_body = ex.read().decode("utf-8", errors="replace")
                    err_json = json.loads(err_body)
                    error_msg = err_json.get("error", {}).get("message", error_msg)
                except Exception:
                    pass
                raise AIProviderError(f"OpenAI request failed: {error_msg}") from ex
        except (TimeoutError, urllib.error.URLError) as ex:
            reason_str = str(getattr(ex, "reason", ex)).lower()
            if isinstance(ex, TimeoutError) or "timed out" in reason_str or "timeout" in reason_str:
                raise AIProviderTimeoutError(f"OpenAI request timed out after {self.timeout} seconds.") from ex
            raise AIProviderError(f"Network error connecting to OpenAI: {getattr(ex, 'reason', str(ex))}") from ex
        except AIProviderError:
            raise
        except Exception as ex:
            raise AIProviderError(f"Unexpected provider error: {str(ex)}") from ex


_ACTIVE_PROVIDER: BaseAIProvider | None = None


def get_ai_provider() -> BaseAIProvider:
    """Returns the singleton AI provider configured by environment."""
    global _ACTIVE_PROVIDER
    if _ACTIVE_PROVIDER is not None:
        return _ACTIVE_PROVIDER

    provider_name = os.environ.get("AI_PROVIDER", "openai").lower().strip()
    if provider_name == "openai":
        _ACTIVE_PROVIDER = OpenAIProvider()
    else:
        # Default fallback to OpenAI provider
        _ACTIVE_PROVIDER = OpenAIProvider()

    return _ACTIVE_PROVIDER


def set_ai_provider(provider: BaseAIProvider):
    """Allows testing harnesses to inject mock providers."""
    global _ACTIVE_PROVIDER
    _ACTIVE_PROVIDER = provider
