import os
import json
import pytest
from src.siem.ingestion import IngestionEngine, LogSource
from src.siem.parser import parse_syslog, parse_json_log, parse_csv_log, parse_line
from src.siem.normalizer import normalize, enrich_event, validate_event
from src.siem.storage import EventStore


class TestIngestion:
    def test_engine_init(self):
        engine = IngestionEngine()
        stats = engine.get_stats()
        assert stats["events_ingested"] == 0
        assert stats["sources_active"] == 0

    def test_add_source(self):
        engine = IngestionEngine()
        source = LogSource("file", "/tmp/test.log", "syslog", "test")
        engine.add_source(source)
        assert engine.get_stats()["sources_total"] == 1

    def test_start_stop(self):
        engine = IngestionEngine()
        engine.add_source(LogSource("file", "/tmp/test.log"))
        engine.start_ingestion()
        assert engine.get_stats()["running"] is True
        engine.stop_ingestion()
        assert engine.get_stats()["running"] is False

    def test_ingest_sample_file_not_found(self):
        engine = IngestionEngine()
        lines = engine.ingest_sample("/nonexistent/path.log")
        assert lines == []


class TestParser:
    def test_parse_syslog(self):
        line = "Jul 25 08:00:01 server01 sshd[1234]: Failed password for root from 45.33.32.156 port 22"
        result = parse_syslog(line)
        assert "host" in result
        assert result["host"] == "server01"

    def test_parse_json(self):
        line = json.dumps({"timestamp": "2026-07-25T08:00:00", "event_type": "login", "status": "success"})
        result = parse_json_log(line)
        assert result["event_type"] == "login"

    def test_parse_csv(self):
        line = "2026-07-25 08:00:00,192.168.1.1,10.0.0.1,connection,high,test message"
        result = parse_csv_log(line)
        assert result["source_ip"] == "192.168.1.1"

    def test_parse_line_dispatch(self):
        line = "Jul 25 08:00:00 host01 test: hello"
        result = parse_line(line, "syslog")
        assert result["host"] == "host01"

    def test_parse_unknown_format(self):
        line = "plain text"
        result = parse_line(line, "unknown")
        assert "raw" in result


class TestNormalizer:
    def test_normalize_basic(self):
        raw = {"timestamp": "2026-07-25T08:00:00", "severity": "err", "message": "test error"}
        event = normalize(raw, "test_source")
        assert event.severity == "high"
        assert event.source == "test_source"

    def test_normalize_unknown_severity(self):
        raw = {"message": "info only"}
        event = normalize(raw)
        assert event.severity == "low"
        assert event.event_type == "unknown"

    def test_enrich_event(self):
        from src.siem.normalizer import NormalizedEvent
        event = NormalizedEvent(source_ip="192.168.1.1")
        enrich_event(event, {})
        assert "internal" in event.tags

    def test_enrich_event_external(self):
        from src.siem.normalizer import NormalizedEvent
        event = NormalizedEvent(source_ip="45.33.32.156")
        enrich_event(event)
        assert "external" in event.tags

    def test_validate_event_valid(self):
        from src.siem.normalizer import NormalizedEvent
        event = NormalizedEvent(timestamp="now", event_type="test")
        assert validate_event(event) is True

    def test_validate_event_invalid(self):
        from src.siem.normalizer import NormalizedEvent
        event = NormalizedEvent(timestamp="", event_type="test")
        assert validate_event(event) is False


class TestStorage:
    def test_store_and_retrieve(self):
        from src.siem.normalizer import NormalizedEvent
        store = EventStore()
        event = NormalizedEvent(timestamp="t1", event_type="login", severity="high")
        store.store_event(event)
        assert len(store) == 1

    def test_query_by_severity(self):
        from src.siem.normalizer import NormalizedEvent
        store = EventStore()
        store.store_event(NormalizedEvent(timestamp="t1", event_type="login", severity="high"))
        store.store_event(NormalizedEvent(timestamp="t2", event_type="logout", severity="low"))
        results = store.query({"severity": "high"})
        assert len(results) == 1

    def test_statistics(self):
        from src.siem.normalizer import NormalizedEvent
        store = EventStore()
        store.store_event(NormalizedEvent(timestamp="t1", event_type="login", severity="high"))
        store.store_event(NormalizedEvent(timestamp="t2", event_type="login", severity="low"))
        store.store_event(NormalizedEvent(timestamp="t3", event_type="logout", severity="medium"))
        stats = store.get_statistics()
        assert stats["total_events"] == 3
        assert stats["by_type"]["login"] == 2

    def test_clear(self):
        from src.siem.normalizer import NormalizedEvent
        store = EventStore()
        store.store_event(NormalizedEvent(timestamp="t1", event_type="login", severity="high"))
        store.clear()
        assert len(store) == 0
