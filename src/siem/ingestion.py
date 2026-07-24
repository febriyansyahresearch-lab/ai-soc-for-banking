import os
import time
from datetime import datetime
from typing import Optional


class LogSource:
    def __init__(self, source_type: str, path: str, parser: str = "syslog", label: Optional[str] = None):
        self.source_type = source_type
        self.path = path
        self.parser = parser
        self.label = label or os.path.basename(path)
        self.active = False
        self.bytes_read = 0
        self.lines_read = 0

    def __repr__(self) -> str:
        return f"LogSource({self.label}, type={self.source_type}, active={self.active})"


class IngestionEngine:
    def __init__(self):
        self.sources: list[LogSource] = []
        self._running = False
        self._events_ingested = 0
        self._errors = 0

    def add_source(self, source: LogSource) -> None:
        self.sources.append(source)

    def remove_source(self, label: str) -> bool:
        for i, s in enumerate(self.sources):
            if s.label == label:
                self.sources.pop(i)
                return True
        return False

    def start_ingestion(self) -> None:
        self._running = True
        for source in self.sources:
            source.active = True

    def stop_ingestion(self) -> None:
        self._running = False
        for source in self.sources:
            source.active = False

    def ingest_sample(self, path: str) -> list[str]:
        try:
            with open(path, "r") as f:
                lines = f.readlines()
            self._events_ingested += len(lines)
            return [l.strip() for l in lines if l.strip()]
        except FileNotFoundError:
            self._errors += 1
            return []
        except Exception:
            self._errors += 1
            return []

    def get_stats(self) -> dict:
        return {
            "events_ingested": self._events_ingested,
            "sources_active": sum(1 for s in self.sources if s.active),
            "sources_total": len(self.sources),
            "errors": self._errors,
            "running": self._running,
        }
