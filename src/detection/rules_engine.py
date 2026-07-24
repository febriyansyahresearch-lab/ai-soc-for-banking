from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    conditions: dict[str, Any]
    severity: str = "medium"
    tags: list[str] = field(default_factory=list)


BUILTIN_RULES = [
    DetectionRule(
        id="BRUTE-001",
        name="Multiple Failed Logins",
        description="5+ failed authentication attempts within 5 minutes",
        conditions={"event_type": "authentication", "status": "failed", "min_count": 5, "window_minutes": 5},
        severity="high",
        tags=["brute-force", "authentication"],
    ),
    DetectionRule(
        id="GEO-001",
        name="High-Risk Country Connection",
        description="Connection from a high-risk geolocation",
        conditions={"event_type": "connection", "country_risk": "high"},
        severity="high",
        tags=["geo", "threat-intel"],
    ),
    DetectionRule(
        id="PORT-001",
        name="Unusual Port Access",
        description="Access to non-standard ports (not 80, 443, 22, 3306, 5432)",
        conditions={"event_type": "connection", "port": "unusual"},
        severity="medium",
        tags=["network", "recon"],
    ),
    DetectionRule(
        id="HASH-001",
        name="Known Malicious Hash",
        description="File hash matches known malware database",
        conditions={"event_type": "file", "hash_status": "malicious"},
        severity="critical",
        tags=["malware", "hash"],
    ),
    DetectionRule(
        id="PRIV-001",
        name="Privilege Escalation Attempt",
        description="User attempted privilege escalation",
        conditions={"event_type": "authorization", "action": "escalation", "status": "denied"},
        severity="high",
        tags=["privilege-escalation", "authorization"],
    ),
]


class RulesEngine:
    def __init__(self):
        self._rules: list[DetectionRule] = []

    def load_rules(self, rules: list[DetectionRule]) -> None:
        self._rules = rules

    def add_rule(self, rule: DetectionRule) -> None:
        self._rules.append(rule)

    def get_rules(self) -> list[DetectionRule]:
        return list(self._rules)

    def evaluate(self, event: dict) -> list[str]:
        matched = []
        for rule in self._rules:
            conditions_met = 0
            total_conditions = 0
            for key, value in rule.conditions.items():
                if key in ("min_count", "window_minutes", "country_risk", "port"):
                    continue
                total_conditions += 1
                if event.get(key) == value:
                    conditions_met += 1
            if total_conditions > 0 and conditions_met == total_conditions:
                matched.append(rule.id)
            elif total_conditions == 0:
                matched.append(rule.id)
        return matched
