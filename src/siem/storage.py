from datetime import datetime, timedelta
from typing import Any

from src.siem.normalizer import NormalizedEvent


class EventStore:
    def __init__(self):
        self._events: list[NormalizedEvent] = []

    def store_event(self, event: NormalizedEvent) -> None:
        self._events.append(event)

    def store_events(self, events: list[NormalizedEvent]) -> None:
        self._events.extend(events)

    def query(self, filters: dict[str, Any] | None = None) -> list[NormalizedEvent]:
        if not filters:
            return list(self._events)
        results = self._events[:]
        for key, value in filters.items():
            if key == "severity":
                results = [e for e in results if e.severity == value]
            elif key == "event_type":
                results = [e for e in results if e.event_type == value]
            elif key == "source_ip":
                results = [e for e in results if e.source_ip == value]
            elif key == "source":
                results = [e for e in results if e.source == value]
            elif key == "tag":
                results = [e for e in results if value in e.tags]
        return results

    def get_events_by_time_range(self, start: str, end: str) -> list[NormalizedEvent]:
        return [e for e in self._events if start <= e.timestamp <= end]

    def get_events_by_type(self, event_type: str) -> list[NormalizedEvent]:
        return [e for e in self._events if e.event_type == event_type]

    def get_statistics(self) -> dict:
        total = len(self._events)
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for e in self._events:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
        return {"total_events": total, "by_type": by_type, "by_severity": by_severity}

    def clear(self) -> None:
        self._events.clear()

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self):
        return iter(self._events)
