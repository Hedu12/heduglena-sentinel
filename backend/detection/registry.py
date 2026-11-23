"""
Default rule set, built from validated Settings.

This is the only place Settings values are mapped onto rule parameters, so
rules themselves never read configuration or the environment.
"""

from __future__ import annotations

from core.config import Settings
from detection.rules.base import DetectionRule
from detection.rules.network import NetworkAnomalyRule
from detection.rules.process import ProcessCountAnomalyRule
from detection.rules.resource import CpuAnomalyRule, MemoryAnomalyRule
from detection.rules.synthetic_rule import SyntheticPolicy, SyntheticSecurityEventRule
from models.enums import Classification, Severity, SyntheticEventType


def build_synthetic_policies(settings: Settings) -> dict[SyntheticEventType, SyntheticPolicy]:
    """Per-event-type policies for DET-SYN-001."""

    def burst(
        detection_type: str, count: int, window: float, severity: Severity, escalated: Severity
    ) -> SyntheticPolicy:
        return SyntheticPolicy(
            detection_type=detection_type,
            threshold=count,
            window_seconds=window,
            severity=severity,
            classification=Classification.SUSPICIOUS,
            escalation_threshold=count * 2,
            escalated_severity=escalated,
            escalated_classification=Classification.HIGH_CONFIDENCE,
        )

    return {
        SyntheticEventType.AUTH_FAILURE: burst(
            "auth_failure_burst",
            settings.rule_auth_failure_count,
            settings.rule_auth_failure_window_seconds,
            Severity.HIGH,
            Severity.CRITICAL,
        ),
        SyntheticEventType.ACCESS_DENIED: burst(
            "access_denied_burst",
            settings.det_access_denied_count,
            settings.det_access_denied_window_seconds,
            Severity.MEDIUM,
            Severity.HIGH,
        ),
        SyntheticEventType.CONNECTION_BURST: burst(
            "connection_burst",
            settings.det_connection_burst_count,
            settings.det_connection_burst_window_seconds,
            Severity.MEDIUM,
            Severity.HIGH,
        ),
        # A simulated malicious process is a single decisive event.
        SyntheticEventType.SUSPICIOUS_PROCESS: SyntheticPolicy(
            detection_type="suspicious_process",
            threshold=1,
            window_seconds=60.0,
            severity=Severity.CRITICAL,
            classification=Classification.HIGH_CONFIDENCE,
        ),
    }


def build_default_rules(settings: Settings) -> list[DetectionRule]:
    """Build the five Phase 3 rules from configuration."""
    cooldown = settings.det_cooldown_seconds
    return [
        CpuAnomalyRule(
            threshold_percent=settings.det_cpu_threshold_percent,
            consecutive_samples=settings.det_cpu_consecutive_samples,
            cooldown_seconds=cooldown,
        ),
        MemoryAnomalyRule(
            threshold_percent=settings.det_mem_threshold_percent,
            consecutive_samples=settings.det_mem_consecutive_samples,
            cooldown_seconds=cooldown,
        ),
        NetworkAnomalyRule(
            threshold_bytes_per_second=settings.det_net_threshold_bytes_per_second,
            consecutive_samples=settings.det_net_consecutive_samples,
            cooldown_seconds=cooldown,
        ),
        ProcessCountAnomalyRule(
            window_samples=settings.det_proc_window_samples,
            min_baseline_samples=settings.det_proc_min_baseline_samples,
            increase_ratio=settings.det_proc_increase_ratio,
            min_increase=settings.det_proc_min_increase,
            consecutive_samples=settings.det_proc_consecutive_samples,
            cooldown_seconds=cooldown,
        ),
        SyntheticSecurityEventRule(
            policies=build_synthetic_policies(settings),
            cooldown_seconds=cooldown,
        ),
    ]
