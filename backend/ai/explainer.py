"""
Explainer: one context in, one contained outcome out.

    IncidentContext -> prompt -> LLMProvider -> check_output -> ExplanationOutcome

Never raises (except cancellation), never retries indefinitely, never waits
longer than the timeout per attempt. Timeouts and provider errors are retried up
to max_attempts in total; an answer that fails validation is final, because
asking again for the same context invites the same unsafe output.

The outcome is display data. The explainer has no access to, and no way to
reach, the threat scorer, the state machine, the response planner, the guard or
the executor.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from ai.context import IncidentContext
from ai.output import ExplanationOutput, check_output
from ai.prompt import build_request
from ai.protocols import LLMProvider, ProviderResponse
from models.enums import ExplanationFailure, ExplanationStatus

logger = logging.getLogger(__name__)


def _count(value: object) -> int | None:
    """A provider-reported token count, if it is a plausible one."""
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10_000_000:
        return value
    return None


@dataclass(frozen=True, slots=True)
class ExplainerLimits:
    timeout_seconds: float
    max_attempts: int
    max_output_tokens: int
    max_raw_chars: int
    max_field_chars: int
    max_context_chars: int


@dataclass(frozen=True, slots=True)
class ExplanationOutcome:
    """The result of trying to explain one context."""

    status: ExplanationStatus
    provider: str
    output: ExplanationOutput | None = None
    failure: ExplanationFailure | None = None
    detail: str | None = None
    model: str | None = None
    # Bounded, unvalidated provider text for audit (AS-07). Never displayed.
    raw_response: str | None = None
    prompt_tokens: int | None = None
    response_tokens: int | None = None
    latency_ms: int = 0
    attempts: int = 0


class Explainer:
    def __init__(
        self,
        provider: LLMProvider,
        limits: ExplainerLimits,
        *,
        monotonic: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._provider = provider
        self._limits = limits
        self._monotonic = monotonic

    @property
    def provider_name(self) -> str:
        return self._provider.name

    async def explain(self, context: IncidentContext) -> ExplanationOutcome:
        incident_id = context.incident.incident_id
        request = build_request(context, max_output_tokens=self._limits.max_output_tokens)
        if len(request.messages[1].content) > self._limits.max_context_chars:
            return self._failed(ExplanationFailure.CONTEXT_UNAVAILABLE, "context_too_large", 0, 0)

        started = self._monotonic()
        failure = ExplanationFailure.PROVIDER_ERROR
        detail = "no_attempt"
        attempts = 0
        response: ProviderResponse | None = None
        while attempts < self._limits.max_attempts:
            attempts += 1
            try:
                response = await asyncio.wait_for(
                    self._provider.generate_explanation(request),
                    timeout=self._limits.timeout_seconds,
                )
                break
            except TimeoutError:
                failure, detail = ExplanationFailure.TIMEOUT, "timeout"
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Only the exception type is recorded: its text is not trusted audit data.
                failure, detail = ExplanationFailure.PROVIDER_ERROR, type(exc).__name__
            logger.warning(
                "AI: %s attempt %d/%d failed for %s (%s)",
                self._provider.name,
                attempts,
                self._limits.max_attempts,
                incident_id,
                detail,
            )
        latency = self._elapsed_ms(started)
        if response is None:
            return self._failed(failure, detail, latency, attempts)

        if not isinstance(response.text, str):
            return self._failed(ExplanationFailure.EMPTY_RESPONSE, "not_text", latency, attempts)
        raw = response.text
        check = check_output(
            raw,
            max_raw_chars=self._limits.max_raw_chars,
            max_field_chars=self._limits.max_field_chars,
            incident_id=incident_id,
        )
        if check.output is None:
            logger.warning(
                "AI: rejected explanation for %s (%s: %s)",
                incident_id,
                check.failure.value if check.failure else "-",
                check.detail,
            )
        return ExplanationOutcome(
            status=ExplanationStatus.VALID if check.output else ExplanationStatus.REJECTED,
            provider=self._provider.name,
            output=check.output,
            failure=check.failure,
            detail=check.detail,
            model=str(response.model)[:100],
            raw_response=raw[: self._limits.max_raw_chars],
            prompt_tokens=_count(response.prompt_tokens),
            response_tokens=_count(response.response_tokens),
            latency_ms=latency,
            attempts=attempts,
        )

    def _failed(
        self, failure: ExplanationFailure, detail: str, latency: int, attempts: int
    ) -> ExplanationOutcome:
        return ExplanationOutcome(
            status=ExplanationStatus.FAILED,
            provider=self._provider.name,
            failure=failure,
            detail=detail,
            latency_ms=latency,
            attempts=attempts,
        )

    def _elapsed_ms(self, started: float) -> int:
        return max(0, int((self._monotonic() - started) * 1000))
