"""
Central configuration module.

All behavioral parameters are loaded here once at startup from environment
variables or a .env file. No other module calls os.getenv() directly.
See .kiro/steering/architecture-principles.md §P-02.
"""

from __future__ import annotations

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from models.enums import DefenseState


class Settings(BaseSettings):
    """Validated application configuration loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    # live_actions is read by ResponseGuard; demo_mode gates /api/v1/demo (SR-08);
    # frontend_origin is the CORS and WebSocket origin. log_level is reserved for the
    # logging phase (tests/unit/test_settings_usage.py keeps this honest: a setting
    # must be read by code or be listed there).
    demo_mode: bool = Field(default=True)
    live_actions: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    frontend_origin: str = Field(default="http://localhost:3000")

    # ── Telemetry ─────────────────────────────────────────────────────────────
    poll_interval_seconds: float = Field(default=2.0, ge=0.25)

    # ── Runtime: demo scenarios and the live stream (Phase 2) ─────────────────
    # Pause between the synthetic events of a demo scenario (0 = back to back).
    demo_step_interval_seconds: float = Field(default=1.0, ge=0.0, le=10.0)
    # Demo requests (inject + scenario) accepted per rolling minute (TM-02).
    demo_max_requests_per_minute: int = Field(default=30, ge=1, le=600)
    # WebSocket /ws/live: concurrent clients, and messages buffered per client
    # (the oldest are dropped first, so a slow client never blocks the pipeline).
    live_max_subscribers: int = Field(default=8, ge=1, le=64)
    live_queue_size: int = Field(default=200, ge=10, le=5000)

    # ── Defense state machine: timers and entry thresholds ────────────────────
    # (Hysteresis, bypass and floors are in the Phase 4 block below.)
    dwell_seconds: float = Field(default=10.0, ge=1.0)
    cooldown_seconds: float = Field(default=30.0, ge=1.0)
    threshold_relaxed_alert: float = Field(default=0.25, ge=0.0, le=1.0)
    threshold_alert_defensive: float = Field(default=0.55, ge=0.0, le=1.0)
    threshold_defensive_aggressive: float = Field(default=0.80, ge=0.0, le=1.0)

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = Field(default="sqlite+aiosqlite:///./sentinel.db")

    # ── AI explanation layer (Phase 6) ────────────────────────────────────────
    # Explanation-only: nothing in the security pipeline reads these.
    # "null" (default) is deterministic and makes no network calls (AS-09).
    ai_provider: str = Field(default="null")
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3.2")
    # Never logged or echoed: SecretStr masks it in repr and model dumps.
    openai_api_key: SecretStr = Field(default=SecretStr(""))
    openai_base_url: str = Field(default="https://api.openai.com/v1")
    openai_model: str = Field(default="gpt-4o-mini")
    # Per-field cap passed to AIOutputValidator (AS-03 step 1).
    ai_max_response_chars: int = Field(default=2000, ge=100)
    # Raw provider output larger than this is rejected before parsing. The upper bound is
    # the hard audit cap on stored raw_response (16,000 characters, also a database CHECK).
    ai_max_raw_response_chars: int = Field(default=8000, ge=1000, le=16_000)
    # Prompt context (JSON) larger than this is not sent.
    ai_max_context_chars: int = Field(default=24_000, ge=2000, le=200_000)
    ai_max_output_tokens: int = Field(default=500, ge=50, le=1000)  # AS-05 explain_incident
    # One provider call may take at most this long; then it counts as failed.
    ai_explanation_timeout_seconds: float = Field(default=10.0, gt=0.0, le=120.0)
    # Attempts per explanation (timeouts and provider errors only; invalid output is final).
    ai_max_attempts: int = Field(default=2, ge=1, le=3)
    # Bounded context: AS-02 allows at most 10 detection events.
    # Upper bounds equal the AS-02 hard caps: configuration can narrow the context, never widen it.
    ai_max_context_events: int = Field(default=10, ge=1, le=10)
    ai_max_context_transitions: int = Field(default=8, ge=1, le=8)
    ai_max_context_actions: int = Field(default=10, ge=1, le=10)
    # While AGGRESSIVE, refresh the explanation at most this often (decision time).
    # The floor prevents excessive LLM calls.
    ai_aggressive_refresh_seconds: float = Field(default=30.0, ge=10.0, le=3600.0)
    # A score rise this large since the last explanation counts as significant new evidence.
    ai_evidence_score_delta: float = Field(default=0.15, gt=0.0, le=1.0)
    # Incidents that may wait for an explanation at once; further requests are dropped.
    ai_queue_max_incidents: int = Field(default=32, ge=1, le=1000)

    # ── Detection engine (Phase 3) ────────────────────────────────────────────
    # Authentication-failure bursts (DET-SYN-001) use these two settings.
    rule_auth_failure_count: int = Field(default=5, ge=1)
    rule_auth_failure_window_seconds: int = Field(default=60, ge=10)
    # Debounce: minimum seconds between repeat events from the same rule/key,
    # measured on telemetry/event timestamps (not the wall clock).
    det_cooldown_seconds: float = Field(default=60.0, ge=0.0)
    # DET-CPU-001 / DET-MEM-001: sustained utilisation (percent, consecutive samples).
    det_cpu_threshold_percent: float = Field(default=90.0, ge=0.0, le=100.0)
    det_cpu_consecutive_samples: int = Field(default=3, ge=1, le=1000)
    det_mem_threshold_percent: float = Field(default=90.0, ge=0.0, le=100.0)
    det_mem_consecutive_samples: int = Field(default=3, ge=1, le=1000)
    # DET-NET-001: per-direction throughput in bytes per second.
    det_net_threshold_bytes_per_second: float = Field(default=50_000_000.0, gt=0.0)
    det_net_consecutive_samples: int = Field(default=3, ge=1, le=1000)
    # DET-PROC-001: deviation from a bounded rolling baseline of process counts.
    det_proc_window_samples: int = Field(default=30, ge=5, le=1000)
    det_proc_min_baseline_samples: int = Field(default=10, ge=3, le=1000)
    det_proc_increase_ratio: float = Field(default=1.5, gt=1.0)
    det_proc_min_increase: int = Field(default=50, ge=1)
    det_proc_consecutive_samples: int = Field(default=2, ge=1, le=1000)
    # DET-SYN-001: other synthetic security events (see rule_auth_failure_* above).
    det_access_denied_count: int = Field(default=5, ge=1, le=10_000)
    det_access_denied_window_seconds: int = Field(default=60, ge=1)
    det_connection_burst_count: int = Field(default=20, ge=1, le=10_000)
    det_connection_burst_window_seconds: int = Field(default=30, ge=1)

    # ── Threat scoring (Phase 4) ──────────────────────────────────────────────
    # Score = clamp(severity + confidence + repetition + escalation
    #               + correlation + cross_domain), each term bounded by its weight.
    threat_weight_severity: float = Field(default=0.45, ge=0.0, le=1.0)
    threat_weight_confidence: float = Field(default=0.15, ge=0.0, le=1.0)
    threat_weight_repetition: float = Field(default=0.10, ge=0.0, le=1.0)
    threat_weight_escalation: float = Field(default=0.10, ge=0.0, le=1.0)
    threat_weight_correlation: float = Field(default=0.20, ge=0.0, le=1.0)
    threat_weight_cross_domain: float = Field(default=0.10, ge=0.0, le=1.0)
    # Contribution of each additional independent category, before the cap above.
    threat_correlation_per_category: float = Field(default=0.15, ge=0.0, le=1.0)
    # Severity -> risk level in [0, 1]. Must be non-decreasing.
    threat_level_info: float = Field(default=0.10, ge=0.0, le=1.0)
    threat_level_low: float = Field(default=0.20, ge=0.0, le=1.0)
    threat_level_medium: float = Field(default=0.40, ge=0.0, le=1.0)
    threat_level_high: float = Field(default=0.70, ge=0.0, le=1.0)
    threat_level_critical: float = Field(default=1.00, ge=0.0, le=1.0)
    # Repetition saturates: 1 - exp(-(n-1)/scale), with n capped at the cap.
    threat_repetition_scale: float = Field(default=3.0, gt=0.0)
    threat_repetition_cap: int = Field(default=100, ge=2)
    # Evidence loses half its weight every half-life and is dropped after the TTL.
    # The default equals the detection debounce (det_cooldown_seconds), so an
    # ongoing signal re-reported once per debounce period keeps >= half its weight.
    threat_half_life_seconds: float = Field(default=60.0, gt=0.0)
    threat_evidence_ttl_seconds: float = Field(default=300.0, gt=0.0)
    # Evidence younger than this counts as an "active threat" for the state floor.
    threat_active_window_seconds: float = Field(default=60.0, gt=0.0)
    # Hard memory bounds.
    threat_max_signals: int = Field(default=64, ge=1)
    threat_dedup_window: int = Field(default=1024, ge=1)
    # Used when a detection event has no confidence ("not assessed").
    threat_default_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    # Minimum score change worth persisting as a new threat_scores row.
    threat_score_persist_min_delta: float = Field(default=0.01, ge=0.0, le=1.0)

    # ── Defense state machine (Phase 4) ───────────────────────────────────────
    # A state is left only when the score falls this far below its entry threshold.
    threat_hysteresis_margin: float = Field(default=0.05, ge=0.0, le=0.5)
    # A score this far above an entry threshold skips the dwell time.
    threat_escalation_bypass_margin: float = Field(default=0.10, ge=0.0, le=1.0)
    # Active CRITICAL / HIGH evidence keeps the state at least this high.
    # Neither floor may be AGGRESSIVE: that state is reachable only through the
    # score (with dwell, or a corroborated bypass), never through a floor.
    threat_floor_critical: DefenseState = Field(default=DefenseState.DEFENSIVE)
    threat_floor_high: DefenseState = Field(default=DefenseState.ALERT)
    # The bypass into AGGRESSIVE additionally needs this many independent signal
    # categories, each at least this strong, so one event cannot trigger it alone.
    threat_aggressive_min_categories: int = Field(default=2, ge=1, le=8)
    threat_corroboration_min_strength: float = Field(default=0.15, gt=0.0, le=1.0)
    # A new escalation within this long of the previous one ending continues the same
    # situation instead of starting a new one (so RECORD_INCIDENT is not repeated).
    threat_incident_reopen_seconds: float = Field(default=300.0, ge=0.0)

    # ── Response engine (Phase 5) ─────────────────────────────────────────────
    # Cooldowns measured on decision timestamps (not the wall clock), so response
    # behaviour is deterministic for a given decision sequence.
    # After a BLOCKED or FAILED attempt, wait this long before trying the same scope again.
    response_retry_cooldown_seconds: float = Field(default=30.0, ge=0.0)
    # Alerts outside any situation (evidence while RELAXED) at most this often.
    response_alert_cooldown_seconds: float = Field(default=60.0, ge=0.0)

    @model_validator(mode="after")
    def validate_threat_model(self) -> Settings:
        levels = [
            self.threat_level_info,
            self.threat_level_low,
            self.threat_level_medium,
            self.threat_level_high,
            self.threat_level_critical,
        ]
        if levels != sorted(levels):
            raise ValueError("threat_level_* must be non-decreasing from info to critical")
        entries = [
            self.threshold_relaxed_alert,
            self.threshold_alert_defensive,
            self.threshold_defensive_aggressive,
        ]
        if not all(a < b for a, b in zip(entries, entries[1:], strict=False)):
            raise ValueError("state thresholds must be strictly increasing")
        gaps = [entries[0], *(b - a for a, b in zip(entries, entries[1:], strict=False))]
        if self.threat_hysteresis_margin >= min(gaps):
            raise ValueError("threat_hysteresis_margin must be smaller than every threshold gap")
        order = list(DefenseState)
        if order.index(self.threat_floor_critical) < order.index(self.threat_floor_high):
            raise ValueError("threat_floor_critical must not be below threat_floor_high")
        for floor in (self.threat_floor_critical, self.threat_floor_high):
            if floor is DefenseState.AGGRESSIVE:
                raise ValueError("a state floor must not be AGGRESSIVE")
        return self

    @model_validator(mode="after")
    def validate_detection_windows(self) -> Settings:
        if self.det_proc_min_baseline_samples > self.det_proc_window_samples:
            raise ValueError(
                "det_proc_min_baseline_samples must not exceed det_proc_window_samples"
            )
        return self

    @model_validator(mode="after")
    def validate_cloud_ai_is_explicit(self) -> Settings:
        # AS-09: a cloud provider needs an explicit choice AND a key; refuse to start otherwise.
        if self.ai_provider == "openai" and not self.openai_api_key.get_secret_value():
            raise ValueError("ai_provider=openai requires OPENAI_API_KEY")
        return self

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: str) -> str:
        allowed = {"null", "ollama", "openai"}
        if v not in allowed:
            raise ValueError(f"ai_provider must be one of {allowed}, got {v!r}")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return upper


# Module-level singleton — imported by all other modules.
settings = Settings()
