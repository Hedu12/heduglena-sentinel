"""
The AI provider port (P-03).

An LLMProvider turns one ExplanationRequest into text. That is all it can do:
the request carries no tools, functions or callbacks, and nothing a provider
returns is ever executed or passed to a security component. Concrete adapters
live in ai.adapters; the rest of Sentinel depends only on this protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from ai.context import IncidentContext


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: Literal["system", "user"]
    content: str


@dataclass(frozen=True, slots=True)
class ExplanationRequest:
    """
    One explanation request. messages[0] is always the mandatory system prompt
    (AS-01). `context` is the same sanitised data already serialised into the
    user message; it lets deterministic providers work without parsing prompts.
    """

    incident_id: str
    messages: tuple[ChatMessage, ...]
    max_output_tokens: int
    context: IncidentContext


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """What a provider returned, unvalidated."""

    text: str
    model: str
    prompt_tokens: int | None = None
    response_tokens: int | None = None


@runtime_checkable
class LLMProvider(Protocol):
    """Implemented by NullProvider, FakeLLMProvider and OpenAICompatibleProvider."""

    @property
    def name(self) -> str:
        """Provider identifier recorded with every explanation (AS-07)."""
        ...

    async def generate_explanation(self, request: ExplanationRequest) -> ProviderResponse:
        """Return the model's raw answer. May raise; the caller contains every failure."""
        ...
