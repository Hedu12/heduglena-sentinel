"""
Latency statistics and cost estimation.

Latency is measured by the production Explainer around the provider call (all
attempts of one case). Only cases where the provider answered count: a timeout
is a failure with its own rate, not a latency sample.

Cost is never invented. The provider adapter does not surface a provider-reported
cost, so ACTUAL_PROVIDER_REPORTED_COST is never produced today; with evaluator-
configured prices and provider-reported token counts the cost is
ESTIMATED_CONFIGURED_COST; otherwise it is cost_unavailable with a reason code.
"""

from __future__ import annotations

import math
import statistics
from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from evaluation.matrix import Pricing
from evaluation.report import CaseResult


class LatencyStats(BaseModel):
    model_config = ConfigDict(frozen=True)

    samples: int
    min_ms: int | None = None
    mean_ms: float | None = None
    median_ms: float | None = None
    p95_ms: int | None = None  # None when there are too few samples
    max_ms: int | None = None


def p95(values: Sequence[int]) -> int:
    """Nearest-rank 95th percentile of a non-empty sequence."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def latency_stats(cases: Sequence[CaseResult], *, min_p95_samples: int) -> LatencyStats:
    values = [c.latency_ms for c in cases if c.responded]
    if not values:
        return LatencyStats(samples=0)
    return LatencyStats(
        samples=len(values),
        min_ms=min(values),
        mean_ms=round(statistics.fmean(values), 1),
        median_ms=float(statistics.median(values)),
        p95_ms=p95(values) if len(values) >= min_p95_samples else None,
        max_ms=max(values),
    )


class CostSource(StrEnum):
    ACTUAL_PROVIDER_REPORTED_COST = "ACTUAL_PROVIDER_REPORTED_COST"
    ESTIMATED_CONFIGURED_COST = "ESTIMATED_CONFIGURED_COST"
    COST_UNAVAILABLE = "cost_unavailable"


class CostEstimate(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: CostSource
    reason: str | None = None  # why it is unavailable
    currency: str | None = None
    per_evaluation: float | None = None
    per_100: float | None = None
    per_1000: float | None = None
    priced_cases: int = 0


def estimate_cost(cases: Sequence[CaseResult], pricing: Pricing | None) -> CostEstimate:
    if pricing is None:
        return CostEstimate(source=CostSource.COST_UNAVAILABLE, reason="PRICING_NOT_CONFIGURED")
    priced = [
        c.prompt_tokens * pricing.input_per_million_tokens / 1e6
        + c.response_tokens * pricing.output_per_million_tokens / 1e6
        for c in cases
        if c.responded and c.prompt_tokens is not None and c.response_tokens is not None
    ]
    if not priced:
        return CostEstimate(source=CostSource.COST_UNAVAILABLE, reason="TOKEN_COUNTS_UNAVAILABLE")
    per = statistics.fmean(priced)
    return CostEstimate(
        source=CostSource.ESTIMATED_CONFIGURED_COST,
        currency=pricing.currency,
        per_evaluation=round(per, 8),
        per_100=round(per * 100, 6),
        per_1000=round(per * 1000, 6),
        priced_cases=len(priced),
    )
