from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


@dataclass
class CorrelationRule:
    id: str
    name: str
    conditions: list[dict[str, Any]]
    window_minutes: int = 10
    severity: str = "high"


BUILTIN_CORRELATION_RULES = [
    CorrelationRule(
        id="CORR-SCAN-BRUTE",
        name="Network Scan Followed by Brute Force",
        conditions=[
            {"event_type": "connection", "action": "scan"},
            {"event_type": "authentication", "status": "failed"},
        ],
        window_minutes=15,
        severity="critical",
    ),
    CorrelationRule(
        id="CORR-MALWARE-C2",
        name="Malware Alert with Beaconing",
        conditions=[
            {"event_type": "malware", "action": "detected"},
            {"event_type": "connection", "action": "beacon"},
        ],
        window_minutes=30,
        severity="critical",
    ),
    CorrelationRule(
        id="CORR-PHISH-CRED",
        name="Phishing Followed by Credential Use",
        conditions=[
            {"event_type": "phishing", "action": "reported"},
            {"event_type": "authentication", "status": "success"},
        ],
        window_minutes=60,
        severity="high",
    ),
]


@dataclass
class CorrelatedIncident:
    id: str
    rule_id: str
    rule_name: str
    events: list[dict]
    severity: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "event_count": len(self.events),
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


class CorrelationEngine:
    def __init__(self):
        self._rules: list[CorrelationRule] = []
        self._events: list[dict] = []
        self._incidents: list[CorrelatedIncident] = []
        self._counter = 0

    def add_rule(self, rule: CorrelationRule) -> None:
        self._rules.append(rule)

    def add_event(self, event: dict) -> None:
        self._events.append(event)

    def get_rules(self) -> list[CorrelationRule]:
        return list(self._rules)

    def evaluate(self) -> list[CorrelatedIncident]:
        new_incidents = []
        for rule in self._rules:
            matched_sets = []
            for condition in rule.conditions:
                matched = [e for e in self._events if self._matches_condition(e, condition)]
                if not matched:
                    break
                matched_sets.append(matched)
            if len(matched_sets) == len(rule.conditions):
                ids = []
                for s in matched_sets:
                    ids.append(s[0].get("id", ""))
                self._counter += 1
                incident = CorrelatedIncident(
                    id=f"INC-{self._counter:04d}",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    events=[e for s in matched_sets for e in s],
                    severity=rule.severity,
                    timestamp=datetime.now().isoformat(),
                )
                new_incidents.append(incident)
                self._incidents.append(incident)
        return new_incidents

    def _matches_condition(self, event: dict, condition: dict) -> bool:
        for key, value in condition.items():
            if event.get(key) != value:
                return False
        return True

    def get_incidents(self) -> list[CorrelatedIncident]:
        return list(self._incidents)
