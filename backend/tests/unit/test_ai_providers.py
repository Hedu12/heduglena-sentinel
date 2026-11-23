"""Provider adapters and configuration. No network: httpx.MockTransport only."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from ai.adapters.null_adapter import NullProvider
from ai.adapters.openai_compatible import OpenAICompatibleProvider
from ai.factory import build_provider, explainer_limits
from ai.prompt import SYSTEM_PROMPT, build_request
from ai.protocols import LLMProvider
from core.config import Settings
from core.exceptions import AIProviderError
from tests.ai_helpers import answer, context

REQUEST = build_request(context(), max_output_tokens=500)


def provider(handler: httpx.MockTransport, *, key: str | None = None) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        name="test",
        base_url="http://llm.local/v1",
        model="m-1",
        timeout_seconds=1.0,
        api_key=SecretStr(key) if key is not None else None,
        transport=handler,
    )


def ok(body: dict[str, object] | None = None) -> httpx.MockTransport:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json=body
            or {
                "model": "m-1-served",
                "choices": [{"message": {"content": answer()}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 80},
            },
        )

    transport = httpx.MockTransport(handle)
    transport.seen = seen  # type: ignore[attr-defined]
    return transport


class TestOpenAICompatibleProvider:
    async def test_it_returns_the_message_content_and_usage(self) -> None:
        response = await provider(ok()).generate_explanation(REQUEST)
        assert response.text == answer()
        assert (response.model, response.prompt_tokens, response.response_tokens) == (
            "m-1-served",
            120,
            80,
        )

    async def test_the_request_offers_no_tools_and_caps_tokens(self) -> None:
        transport = ok()
        await provider(transport).generate_explanation(REQUEST)
        (sent,) = transport.seen  # type: ignore[attr-defined]
        body = json.loads(sent.content)
        assert not {"tools", "functions", "tool_choice", "function_call"} & set(body)
        assert body["max_tokens"] == 500 and body["temperature"] == 0
        assert body["messages"][0] == {"role": "system", "content": SYSTEM_PROMPT}
        assert [m["role"] for m in body["messages"]] == ["system", "user"]
        assert sent.url == httpx.URL("http://llm.local/v1/chat/completions")

    async def test_the_key_goes_only_in_the_authorization_header(self) -> None:
        transport = ok()
        await provider(transport, key="sk-test-secret").generate_explanation(REQUEST)
        (sent,) = transport.seen  # type: ignore[attr-defined]
        assert sent.headers["Authorization"] == "Bearer sk-test-secret"
        assert b"sk-test-secret" not in sent.content

    async def test_no_key_means_no_authorization_header(self) -> None:
        transport = ok()
        await provider(transport).generate_explanation(REQUEST)
        (sent,) = transport.seen  # type: ignore[attr-defined]
        assert "Authorization" not in sent.headers

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(500, text="internal error sk-leak"),
            httpx.Response(401, json={"error": "bad key"}),
            httpx.Response(200, text="not json"),
            httpx.Response(200, json={"choices": []}),
            httpx.Response(200, json={"choices": [{"message": {"content": None}}]}),
            httpx.Response(200, content=b"x" * 1_000_001),
        ],
    )
    async def test_bad_responses_raise_a_provider_error_without_the_body(
        self, response: httpx.Response
    ) -> None:
        transport = httpx.MockTransport(lambda _r: response)
        with pytest.raises(AIProviderError) as raised:
            await provider(transport).generate_explanation(REQUEST)
        assert "sk-leak" not in str(raised.value)

    async def test_a_connection_failure_raises_a_provider_error(self) -> None:
        def refuse(_r: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        with pytest.raises(AIProviderError):
            await provider(httpx.MockTransport(refuse)).generate_explanation(REQUEST)

    async def test_redirects_are_not_followed(self) -> None:
        transport = httpx.MockTransport(
            lambda _r: httpx.Response(302, headers={"Location": "http://elsewhere/"})
        )
        with pytest.raises(AIProviderError):
            await provider(transport).generate_explanation(REQUEST)

    def test_only_http_urls_are_accepted(self) -> None:
        with pytest.raises(ValueError):
            OpenAICompatibleProvider(
                name="x", base_url="file:///etc/x", model="m", timeout_seconds=1
            )


class TestConfiguration:
    def test_the_default_provider_is_the_offline_null_provider(self) -> None:
        assert Settings.model_fields["ai_provider"].default == "null"
        assert isinstance(build_provider(Settings()), NullProvider)

    def test_every_provider_satisfies_the_protocol(self) -> None:
        for name in ("null", "ollama"):
            assert isinstance(build_provider(Settings(ai_provider=name)), LLMProvider)
        cloud = Settings(ai_provider="openai", openai_api_key=SecretStr("sk-x"))
        assert isinstance(build_provider(cloud), OpenAICompatibleProvider)

    def test_openai_requires_an_explicit_key(self) -> None:
        with pytest.raises(ValidationError):
            Settings(ai_provider="openai")

    def test_unknown_providers_are_refused(self) -> None:
        with pytest.raises(ValidationError):
            Settings(ai_provider="anything")

    def test_the_key_is_masked_everywhere(self) -> None:
        settings = Settings(ai_provider="openai", openai_api_key=SecretStr("sk-very-secret"))
        assert "sk-very-secret" not in repr(settings)
        assert "sk-very-secret" not in settings.model_dump_json()

    def test_the_refresh_interval_has_a_safe_minimum(self) -> None:
        with pytest.raises(ValidationError):
            Settings(ai_aggressive_refresh_seconds=5)
        assert Settings().ai_aggressive_refresh_seconds == 30

    def test_limits_follow_the_settings(self) -> None:
        limits = explainer_limits(Settings())
        assert limits.max_output_tokens == 500  # AS-05
        assert limits.max_field_chars == 2000  # AS-03
        assert limits.max_attempts == 2
