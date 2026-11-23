"""
Explainability domain service (Phase 6).

Sits downstream of the security domain: it reads authoritative state
(read-only), builds the sanitised context for the AI layer, decides when an
explanation is due, records explanations, and serves read-only incident views.
It never imports the response engine and has no way to affect scoring, state,
planning, authorisation or execution. Nothing in threat/, response/,
detection/ or telemetry/ imports it.
"""
