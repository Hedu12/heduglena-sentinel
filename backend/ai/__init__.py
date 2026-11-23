"""
The explanation-only AI layer (Phase 6).

Authoritative security state -> sanitised IncidentContext -> LLMProvider
-> output validation (schema, policy, AIOutputValidator) -> explanation.

This package has no authority. It imports nothing from the response engine,
the threat service, scoring or the state machine, detection, telemetry or the
database, and nothing in those layers imports it (tests/security/
test_ai_boundary.py). Its output is display text only.
"""
