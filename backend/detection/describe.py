"""
Human-readable descriptions of detection results.

Descriptions are derived from the structured evidence, never the other way
round, and are for display only. They interpolate numbers and fixed words
only: untrusted labels (such as a synthetic event's subject) are deliberately
excluded so a hostile string can never reach a log line, dashboard, or prompt
through this path.
"""

from __future__ import annotations

from collections.abc import Callable

from detection.types import DetectionResult, Evidence


def _num(evidence: Evidence, key: str) -> float | None:
    value = evidence.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _text(evidence: Evidence, key: str) -> str | None:
    value = evidence.get(key)
    return value if isinstance(value, str) else None


def _sustained_percent(label: str) -> Callable[[Evidence], str | None]:
    def build(e: Evidence) -> str | None:
        observed, threshold = _num(e, "observed"), _num(e, "threshold")
        samples = _num(e, "consecutive_samples")
        if observed is None or threshold is None or samples is None:
            return None
        return (
            f"{label} was {observed:.1f}% (threshold {threshold:.1f}%) "
            f"for {int(samples)} consecutive samples."
        )

    return build


def _network(e: Evidence) -> str | None:
    observed, threshold = _num(e, "observed"), _num(e, "threshold")
    samples, direction = _num(e, "consecutive_samples"), _text(e, "direction")
    if observed is None or threshold is None or samples is None or direction is None:
        return None
    return (
        f"{direction} network throughput was {observed / 1e6:.2f} MB/s "
        f"(threshold {threshold / 1e6:.2f} MB/s) for {int(samples)} consecutive samples."
    )


def _process(e: Evidence) -> str | None:
    observed, threshold, mean = _num(e, "observed"), _num(e, "threshold"), _num(e, "baseline_mean")
    if observed is None or threshold is None or mean is None:
        return None
    return (
        f"Process count reached {int(observed)} against a baseline of {mean:.0f} "
        f"(alert level {threshold:.0f})."
    )


def _burst(label: str) -> Callable[[Evidence], str | None]:
    def build(e: Evidence) -> str | None:
        count, threshold, window = (
            _num(e, "observed_count"),
            _num(e, "threshold"),
            _num(e, "window_seconds"),
        )
        if count is None or threshold is None or window is None:
            return None
        return (
            f"{int(count)} {label} within {window:.0f}s (threshold {int(threshold)}). "
            "Synthetic demonstration event."
        )

    return build


_BUILDERS: dict[str, Callable[[Evidence], str | None]] = {
    "cpu_sustained_high": _sustained_percent("CPU utilization"),
    "memory_sustained_high": _sustained_percent("Memory utilization"),
    "network_throughput_high": _network,
    "process_count_anomaly": _process,
    "auth_failure_burst": _burst("authentication failures"),
    "access_denied_burst": _burst("access-denied events"),
    "connection_burst": _burst("connection attempts"),
    "suspicious_process": lambda _e: "A simulated suspicious process event was reported.",
}


def describe(result: DetectionResult) -> str:
    """Return a one-sentence description of a detection result."""
    builder = _BUILDERS.get(result.event_type)
    text = builder(result.evidence) if builder else None
    return text or f"{result.rule_name} ({result.event_type})."
