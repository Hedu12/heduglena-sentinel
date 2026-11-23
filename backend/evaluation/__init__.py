"""
AI explanation evaluation framework (Phase 7).

    benchmark case (sanitised IncidentContext + expected facts)
      -> LLMProvider (via the production Explainer: same prompt, same validation)
      -> deterministic metric checks -> case score -> evaluation report

Offline tooling, not part of the runtime. It reads no database, imports nothing
from the response engine, the threat service, scoring, the state machine,
detection, telemetry or the explanation service, and nothing in Sentinel
imports it (tests/security/test_eval_boundary.py). It cannot affect a security
decision.
"""
