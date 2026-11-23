"""
Application exception hierarchy.

All Sentinel-specific exceptions inherit from SentinelError.
FastAPI route handlers catch these and map them to HTTP responses.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base exception for all application-specific errors."""


class ConfigurationError(SentinelError):
    """Raised when configuration is invalid or missing."""


class TelemetryError(SentinelError):
    """Raised when telemetry collection fails unrecoverably."""


class DetectionError(SentinelError):
    """Raised when the detection engine encounters an unexpected state."""


class RuleNotFoundError(DetectionError):
    """Raised when a rule ID does not exist in the registry."""


class ResponseGuardError(SentinelError):
    """Raised when a response action is blocked by ResponseGuard."""


class AIProviderError(SentinelError):
    """Raised when an AI provider call fails."""


class DatabaseError(SentinelError):
    """Raised when a database operation fails after retries."""
