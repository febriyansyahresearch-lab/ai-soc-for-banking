import math
from typing import Any


class AnomalyDetector:
    def __init__(self):
        self._baseline: dict[str, float] = {}
        self._threshold: float = 2.0

    def train(self, events: list[dict]) -> None:
        values: list[float] = []
        for event in events:
            val = self._extract_value(event)
            if val is not None:
                values.append(val)
        if not values:
            return
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = math.sqrt(variance) if variance > 0 else 1.0
        self._baseline = {"mean": mean, "std": std, "n": len(values)}

    def _extract_value(self, event: dict) -> float | None:
        for key in ("value", "count", "score", "duration", "bytes"):
            if key in event:
                try:
                    return float(event[key])
                except (ValueError, TypeError):
                    return None
        return None

    def detect(self, event: dict) -> float:
        if not self._baseline:
            return 0.0
        val = self._extract_value(event)
        if val is None:
            return 0.0
        mean = self._baseline.get("mean", 0.0)
        std = self._baseline.get("std", 1.0)
        if std == 0:
            return 0.0
        z_score = abs(val - mean) / std
        score = min(1.0, z_score / 5.0)
        return round(score, 4)

    def get_threshold(self) -> float:
        return self._threshold

    def set_threshold(self, value: float) -> None:
        self._threshold = value

    def is_anomalous(self, event: dict) -> bool:
        return self.detect(event) >= self._threshold
