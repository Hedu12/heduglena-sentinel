# AI Safety Requirements — HEDUGLENA Sentinel

These requirements govern every interaction between the system and any AI/LLM provider.  
They apply to all adapters: Ollama, OpenAI-compatible, and any future addition.

---

## Principle: AI is Advisory, Not Executive

The AI subsystem may read operational data and produce text. It may never trigger, authorize, or modify any system action. The only pathway from AI output to system behavior is a human reading the explanation panel on the dashboard.

---

## AS-01: Mandatory System Prompt

Every call to any AI provider must include a system message as the first message in the conversation. The system message must contain the following verbatim text (or equivalent in the provider's format):

> You are a cybersecurity analyst assistant for HEDUGLENA Sentinel. Your role is to explain security events, summarize evidence, and suggest defensive actions in plain English.
>
> STRICT RULES — YOU MUST FOLLOW THESE IN EVERY RESPONSE:
> 1. Do not include executable commands, shell scripts, or terminal syntax of any kind.
> 2. Do not include absolute file system paths (e.g., /etc/passwd, C:\Windows).
> 3. Do not include URLs that could be used to download files.
> 4. Do not instruct the reader to run any program or modify any system configuration.
> 5. Your output is display text only. It will be shown to a human analyst, not executed.

---

## AS-02: Explanation Context (Telemetry Isolation)

**Rule:** The AI receives only the `IncidentContext` defined here (`backend/ai/context.py`),
built by the security domain from authoritative records. This section is the single
authoritative definition of that context; `sentinel-spec.md` §10.5 refers to it.
`tests/security/test_as02_sync.py` fails if the implementation and this section drift.

**Allowed** (every field the AI may receive; nothing else):
- Incident: `SIT-n` incident ID (the only identifier sent), whether it is recorded, status,
  and the safe timestamps `created_at`, `recovered_at`, `resolved_at`, plus the resolution code.
- Current and previous defense state, current threat score, evaluation time, trigger type.
- Derived score breakdown: each contribution (severity, confidence, repetition,
  escalation, correlation, cross-domain), score before decay, decay, active signal
  categories, corroborating-category count.
- Reason codes with their fixed, Sentinel-authored descriptions.
- Bounded state transitions: from/to state, trigger and previous score, reason, time.
- Bounded detection summaries: event type, category, classification, severity,
  confidence, metric key, observed value, threshold, detection time, age, synthetic flag,
  occurrence count, and a synthetic event's subject as `untrusted_subject` (attacker-
  influenced; sanitised and capped).
- Bounded simulated response summaries: action type, defense state, terminal status,
  guard verdict (`AUTHORIZED` / `DENIED` / `NOT_EVALUATED`), guard reason, simulation
  outcome code, `simulated` (always true), dry-run description (identifiers scrubbed), time.

```as02-allowed
schema_version
trigger
incident.incident_id
incident.recorded
incident.status
incident.created_at
incident.recovered_at
incident.resolved_at
incident.resolution
defense_state
previous_state
threat_score
evaluated_at
score_breakdown.final_score
score_breakdown.score_before_decay
score_breakdown.severity
score_breakdown.confidence
score_breakdown.repetition
score_breakdown.escalation
score_breakdown.correlation
score_breakdown.cross_domain
score_breakdown.decay
score_breakdown.active_categories
score_breakdown.corroborating_categories
reasons[].code
reasons[].description
transitions[].from_state
transitions[].to_state
transitions[].trigger_score
transitions[].previous_score
transitions[].reason.code
transitions[].reason.description
transitions[].at
evidence[].event_type
evidence[].category
evidence[].classification
evidence[].severity
evidence[].confidence
evidence[].metric_key
evidence[].observed_value
evidence[].threshold
evidence[].detected_at
evidence[].age_seconds
evidence[].is_synthetic
evidence[].occurrences
evidence[].untrusted_subject
responses[].action_type
responses[].defense_state
responses[].status
responses[].guard_verdict
responses[].guard_reason
responses[].simulation_outcome
responses[].simulated
responses[].dry_run_description
responses[].at
```

**Limits** (hard caps in the schema; configuration may lower them, never raise them):

```as02-limits
evidence: 10
transitions: 8
responses: 10
reasons: 16
active_categories: 16
label_chars: 64
sentence_chars: 300
```

**Forbidden** (must never enter a prompt or the context):
- Raw telemetry: samples, process lists, `raw_json`, telemetry snapshot dictionaries.
- Raw lifecycle JSON and raw parameter JSON of response actions; `event_data` envelopes.
- Secrets, credentials, tokens, API keys, environment variables, configuration.
- Filesystem paths, command lines, database URLs.
- Event, record and database IDs, situation IDs (other than within `SIT-n`).
- Scope, once and idempotency keys; context fingerprints.
- Previous AI output of any kind (`raw_response`, `content`, `explanation`).
- Implementation details not needed to explain the incident.

```as02-forbidden
situation_id
event_id
event_ids
record_id
id
scope_key
once_key
idempotency_key
lifecycle
parameters
event_data
raw_json
telemetry_sample_id
triggering_event_id
raw_response
content
explanation
context_fingerprint
api_key
database_url
```

All context text is sanitised on construction (control, format and separator characters
removed, unpaired surrogates dropped, length capped) and reaches a prompt only as JSON
(AS-08).

---

## AS-03: Output Validation Pipeline

Before any AI response is stored or displayed, it must pass through `AIOutputValidator`.

**Validation steps, in order:**

1. **Length check:** Truncate to `AI_MAX_RESPONSE_CHARS` (default: 2000 characters).

2. **Shell command scan:** Apply the following regex against the full response. Any match triggers redaction:
   ```
   (rm\s+-[rf]+|del\s+/[fqs]|wget\s+http|curl\s+http|bash\s+-[ci]|sh\s+-[ci]|
    powershell[\s.]+|python\s+-[cm]|pip\s+install|\$\(.*\)|`[^`]+`|
    ;\s*(rm|del|wget|curl|bash|sh)|&&\s*(rm|del|wget|curl))
   ```

3. **Path scan:** Apply path pattern detection:
   ```
   (/[a-z]+/[a-z]+|[A-Z]:\\[A-Za-z]+\\[A-Za-z]+|~\/[a-z]+)
   ```

4. **Redaction:** Replace matched substrings with `[REDACTED BY SAFETY FILTER]`.

5. **Logging:** If any redaction occurred, log at WARNING level with the incident ID, the matched pattern, and the character offset. Store both the raw and sanitized responses.

---

## AS-04: No Code Execution Pathway

**Rule:** There must be no programmatic pathway from AI output to code execution.

**Verification:**
- `AIExplanation.explanation` (the validated field) is only written to the database and read by the API for display.
- The field is never passed to `eval`, `exec`, `subprocess`, or any OS call.
- Code review must check that no new code path sends AI output to an execution function.

---

## AS-05: Token Budget

Each AI call must specify a maximum token count.

| Call type | Max output tokens |
|---|---|
| `explain_incident` | 500 |
| `summarize_evidence` | 300 |
| `recommend_actions` | 200 |

If the provider does not honor the token limit, the output validator's length truncation provides a secondary cap.

---

## AS-06: Failure Handling

If the AI provider returns an error or times out:

1. Log the error at WARNING level with the incident ID and provider name.
2. Store a fallback explanation in the database:
   > "Automated explanation unavailable. Manual analyst review required. Incident ID: [id]. Defense state: [state]. Threat score: [score]."
3. The incident record must be created immediately, without waiting for AI explanation.
4. The dashboard must show the fallback text without indicating a system failure to end users (show a neutral "Explanation pending" label).

---

## AS-07: Audit Trail

Every AI call must produce an `ai_explanations` database record containing:
- `provider`: the adapter name.
- `model`: the model identifier returned by the provider.
- `prompt_tokens`: count if available.
- `response_tokens`: count if available.
- `raw_response`: the unvalidated response from the provider.
- `explanation`: the display text: the validated summary, or the deterministic fallback.

This enables post-hoc review of AI behavior and redaction frequency.

**`raw_response` is an audit artifact; `content` is the canonical explanation.**
- `content` holds the validated structured explanation and is set only when the status is
  `VALID` (enforced by a database CHECK). A rejected or failed attempt has no `content`.
- If `AIOutputValidator` would redact anything, the whole answer is rejected: redacted
  text never becomes `content` or `explanation`.
- `raw_response` may hold a rejected answer for audit. It is capped at 16,000 characters
  (database CHECK), is never returned by the API or shown by the frontend, is never
  included in a later prompt, and is never read by threat scoring, response planning,
  `ResponseGuard` or the executor.
- **Retention:** no retention or deletion policy is defined yet. Records are kept
  indefinitely; a retention period for `raw_response` is a future operational requirement.

---

## AS-08: Prompt Injection Defense

Since telemetry data originates from the host environment (process names, file paths, etc.), it must be treated as untrusted input.

**Controls:**
- All string values from telemetry included in the prompt context must be JSON-serialized, not interpolated.
- Example — Prohibited:
  ```python
  prompt = f"Process '{process_name}' triggered rule {rule_name}"
  ```
- Example — Required:
  ```python
  context = json.dumps({"process_name": process_name, "rule_name": rule_name})
  prompt = f"Analyze this event: {context}"
  ```
- The `IncidentContext` object must be serialized via `model.model_dump_json()` before inclusion in any prompt string.

---

## AS-09: Local-First Default

The default AI provider is `NullAdapter` (no network calls, deterministic fallback text). The Ollama adapter (local LLM) is the recommended production adapter for hackathon use.

Cloud AI providers (OpenAI) must not be enabled unless the operator explicitly sets `AI_PROVIDER=openai` and provides `OPENAI_API_KEY`. This prevents accidental data exfiltration of telemetry summaries.

---

## Compliance Checklist

Before any AI-related code is merged, verify:

- [ ] System prompt contains the mandatory five rules verbatim.
- [ ] `IncidentContext` does not include raw telemetry dictionaries or process lists.
- [ ] `AIOutputValidator` is called before any storage or display of AI response.
- [ ] No code path connects AI output to `subprocess`, `eval`, or `exec`.
- [ ] Token budget parameters are set for the call.
- [ ] Failure handling returns a fallback explanation without raising to the caller.
- [ ] All string values from external data are JSON-serialized before prompt inclusion.
- [ ] `ai_explanations` record is created for both successful and failed calls.
