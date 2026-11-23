"""
OpenAICompatibleProvider: any server speaking the OpenAI chat-completions API.

Used for AI_PROVIDER=ollama (a local Ollama server's OpenAI-compatible endpoint)
and AI_PROVIDER=openai. Nothing here is specific to one commercial vendor.

Safety properties of the request:
  * only the two fixed messages (system prompt first, AS-01) are sent;
  * no "tools", "functions" or "tool_choice" field is ever sent, so the model
    cannot be offered anything to call;
  * max_tokens is always set (AS-05) and temperature is 0;
  * the API key, if any, is sent only in the Authorization header and is never
    logged; error messages carry the HTTP status, not the response body.
"""

from __future__ import annotations

import httpx
from pydantic import SecretStr

from ai.protocols import ExplanationRequest, ProviderResponse
from core.exceptions import AIProviderError

# Responses larger than this are refused before JSON parsing.
MAX_HTTP_RESPONSE_BYTES = 1_000_000


class OpenAICompatibleProvider:
    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        model: str,
        timeout_seconds: float,
        api_key: SecretStr | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL")
        self.name = name
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._timeout = timeout_seconds
        self._api_key = api_key
        self._transport = transport

    def payload(self, request: ExplanationRequest) -> dict[str, object]:
        """The exact JSON body sent for a request."""
        return {
            "model": self._model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "max_tokens": request.max_output_tokens,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "stream": False,
        }

    async def generate_explanation(self, request: ExplanationRequest) -> ProviderResponse:
        headers = {"Content-Type": "application/json"}
        if self._api_key is not None and self._api_key.get_secret_value():
            headers["Authorization"] = f"Bearer {self._api_key.get_secret_value()}"
        async with httpx.AsyncClient(
            timeout=self._timeout, transport=self._transport, follow_redirects=False
        ) as client:
            try:
                reply = await client.post(self._url, json=self.payload(request), headers=headers)
            except httpx.HTTPError as exc:
                raise AIProviderError(
                    f"{self.name}: request failed ({type(exc).__name__})"
                ) from None
        if reply.status_code != 200:
            raise AIProviderError(f"{self.name}: HTTP {reply.status_code}")
        if len(reply.content) > MAX_HTTP_RESPONSE_BYTES:
            raise AIProviderError(f"{self.name}: response too large")
        try:
            body = reply.json()
            message = body["choices"][0]["message"]
            text = message["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise AIProviderError(f"{self.name}: unexpected response shape") from None
        if not isinstance(text, str):
            raise AIProviderError(f"{self.name}: response content is not text")
        usage = body.get("usage") if isinstance(body, dict) else None
        usage = usage if isinstance(usage, dict) else {}
        model = body.get("model") if isinstance(body.get("model"), str) else self._model
        return ProviderResponse(
            text=text,
            model=model,
            prompt_tokens=usage.get("prompt_tokens"),
            response_tokens=usage.get("completion_tokens"),
        )
