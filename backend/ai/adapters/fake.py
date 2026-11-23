"""
FakeLLMProvider: a scripted provider for deterministic tests. No network.

Each call consumes the next script entry:
  * a string            returned as the model's answer;
  * an exception        raised (a provider error);
  * HANG                never answers (exercises the timeout).
When the script is exhausted (or empty), it returns a valid deterministic
explanation. Every request is recorded so tests can inspect exact prompts.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable

from ai.adapters.null_adapter import deterministic_explanation
from ai.protocols import ExplanationRequest, ProviderResponse


class _Hang:
    def __repr__(self) -> str:
        return "HANG"


HANG = _Hang()

ScriptEntry = str | BaseException | _Hang


class FakeLLMProvider:
    def __init__(
        self,
        script: Iterable[ScriptEntry] = (),
        *,
        name: str = "fake",
        model: str = "fake-model-1",
    ) -> None:
        self.name = name
        self._model = model
        self._script = list(script)
        self.calls: list[ExplanationRequest] = []

    async def generate_explanation(self, request: ExplanationRequest) -> ProviderResponse:
        self.calls.append(request)
        entry: ScriptEntry | None = self._script.pop(0) if self._script else None
        if isinstance(entry, _Hang):
            await asyncio.Event().wait()  # never set: only a timeout ends this
        if isinstance(entry, BaseException):
            raise entry
        text = (
            entry
            if isinstance(entry, str)
            else json.dumps(deterministic_explanation(request.context))
        )
        return ProviderResponse(text=text, model=self._model, prompt_tokens=1, response_tokens=1)
