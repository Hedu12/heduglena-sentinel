"""
Deterministic text matching for evaluation: claims about states, actions,
evidence and numbers, recognised by meaning-bearing tokens, not exact wording.

Two alias tables: BROAD aliases decide whether a required fact is *mentioned*
(lenient, for completeness); STRICT aliases decide whether a fact is *claimed*
(conservative, for hallucination), so ordinary words such as "network" in a
dry-run description are not mistaken for a claim of network evidence.
"""

from __future__ import annotations

import re

from models.enums import ActionType, DefenseState

STATES = tuple(s.value for s in DefenseState)

# Every detection event type Sentinel can emit (kept in step with threat.evidence by a test).
KNOWN_EVENT_TYPES = (
    "cpu_sustained_high",
    "memory_sustained_high",
    "network_throughput_high",
    "process_count_anomaly",
    "auth_failure_burst",
    "access_denied_burst",
    "connection_burst",
    "suspicious_process",
)

EVENT_BROAD: dict[str, tuple[str, ...]] = {
    "cpu_sustained_high": ("cpu",),
    "memory_sustained_high": ("memory",),
    "network_throughput_high": ("network", "outbound", "throughput", "bytes sent"),
    "process_count_anomaly": ("process count", "number of processes", "processes"),
    "auth_failure_burst": ("authentication", "failed login", "login failure", "auth failure"),
    "access_denied_burst": ("access denied", "denied access"),
    "connection_burst": ("connection burst", "connections"),
    "suspicious_process": ("suspicious process", "malicious process", "malware"),
}
EVENT_STRICT: dict[str, tuple[str, ...]] = {
    "cpu_sustained_high": ("cpu sustained high", "cpu anomaly", "high cpu"),
    "memory_sustained_high": ("memory sustained high", "memory anomaly", "high memory"),
    "network_throughput_high": (
        "network throughput high",
        "network throughput",
        "outbound traffic",
    ),
    "process_count_anomaly": ("process count anomaly", "process count"),
    "auth_failure_burst": ("auth failure burst", "authentication failure", "failed login"),
    "access_denied_burst": ("access denied burst",),
    "connection_burst": ("connection burst",),
    "suspicious_process": ("suspicious process", "malicious process", "malware"),
}
ACTION_ALIASES: dict[ActionType, tuple[str, ...]] = {
    ActionType.GENERATE_ALERT: ("generate alert",),
    ActionType.INCREASE_MONITORING: ("increase monitoring", "increased monitoring"),
    ActionType.RECORD_INCIDENT: ("record incident",),
    ActionType.SIMULATE_IP_BLOCK: ("simulate ip block", "ip block", "block the source",
                                  "blocked the source", "block the offending"),
    ActionType.SIMULATE_PROCESS_ISOLATE: ("simulate process isolate", "process isolation",
                                         "isolate the process", "isolated the process",
                                         "contain the process", "process containment"),
    ActionType.SIMULATE_QUARANTINE: ("simulate quarantine", "quarantin"),
}  # fmt: skip

_DENIAL = re.compile(
    r"\b(denied|deny|refused|rejected|blocked"
    r"|not (?:executed|performed|authori[sz]ed|run|carried out)"
    r"|was not|wasn't|prevented|did not (?:run|execute|occur))\b"
)
_SCORE_LABEL = re.compile(r"threat score\s*(?:of|is|was|at|:|=)?\s*(\d+(?:\.\d+)?)\s*(%)?")
_DECIMAL = re.compile(r"(?<![\d.])(0\.\d{1,4}|1\.0{1,4})(?![\d.])")
_PERCENT = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d+)?)\s*%")
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
_CLAUSE = re.compile(r"[.;,()!?\n]+")
_STATE_UPPER = re.compile(r"(?<![A-Za-z0-9_])(RELAXED|ALERT|DEFENSIVE|AGGRESSIVE)(?![A-Za-z0-9_])")
_STATE_PHRASE = re.compile(
    r"\b(?:state|posture)\s+(?:is\s+|was\s+|of\s+|to\s+|now\s+)?(relaxed|alert|defensive|aggressive)\b"
    r"|\b(relaxed|alert|defensive|aggressive)\s+(?:state|posture)\b"
)


def norm(text: str) -> str:
    """Lower case, underscores and hyphens as spaces, whitespace collapsed."""
    return " ".join(re.sub(r"[_\-]+", " ", text.lower()).split())


def contains(text: str, phrase: str) -> bool:
    return norm(phrase) in norm(text)


def sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE.split(text) if s.strip()]


def clauses(text: str) -> list[str]:
    return [c.strip() for c in _CLAUSE.split(text) if c.strip()]


def is_denial(text: str) -> bool:
    return _DENIAL.search(text.lower()) is not None


def states_mentioned(text: str) -> set[str]:
    found = set(_STATE_UPPER.findall(text))
    for a, b in _STATE_PHRASE.findall(text.lower()):
        found.add((a or b).upper())
    return found


def state_position(text: str, state: str) -> list[int]:
    return [m.start() for m in re.finditer(rf"\b{state.lower()}\b", text.lower())]


def actions_mentioned(text: str) -> set[ActionType]:
    found = {a for a in ActionType if re.search(rf"(?<![A-Z_]){a.value}(?![A-Z_])", text)}
    lowered = norm(text)
    found |= {a for a, aliases in ACTION_ALIASES.items() if any(x in lowered for x in aliases)}
    return found


def action_in(text: str, action: ActionType) -> bool:
    return action in actions_mentioned(text)


def event_mentioned(text: str, event_type: str, *, strict: bool) -> bool:
    table = EVENT_STRICT if strict else EVENT_BROAD
    lowered = norm(text)
    return norm(event_type) in lowered or any(x in lowered for x in table.get(event_type, ()))


def labelled_scores(text: str) -> list[float]:
    """Numbers the text explicitly calls the threat score."""
    out = []
    for number, percent in _SCORE_LABEL.findall(text.lower()):
        value = float(number)
        out.append(value / 100 if percent or value > 1 else value)
    return out


def numbers_as_scores(text: str) -> list[float]:
    values = [float(x) for x in _DECIMAL.findall(text)]
    values += [float(x) / 100 for x in _PERCENT.findall(text) if float(x) <= 100]
    return values


def words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_']+", text)
