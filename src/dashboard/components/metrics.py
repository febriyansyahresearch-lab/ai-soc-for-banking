from dataclasses import dataclass
from typing import Any


@dataclass
class MetricCard:
    label: str
    value: str
    delta: str = ""
    unit: str = ""

    def render(self) -> dict:
        return {
            "label": self.label,
            "value": self.value,
            "delta": self.delta,
            "unit": self.unit,
        }


@dataclass
class MetricsGrid:
    metrics: list[MetricCard]

    def render(self) -> list[dict]:
        return [m.render() for m in self.metrics]
