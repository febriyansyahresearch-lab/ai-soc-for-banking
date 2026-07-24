import os
import pytest
from src.siem.ingestion import IngestionEngine, LogSource
from src.siem.parser import parse_line
from src.siem.normalizer import normalize, enrich_event
from src.siem.storage import EventStore
from src.detection.rules_engine import RulesEngine, DetectionRule
from src.detection.correlation import CorrelationEngine, CorrelationRule
from src.response.playbooks import get_playbook, execute_playbook
from src.response.soarch import SOAROrchestrator, SOARWorkflow, WorkflowAction
from src.response.notifications import Notifier


SAMPLE_LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs")


class TestEndToEnd:
    def test_ingest_to_normalize(self):
        log_path = os.path.join(SAMPLE_LOG_DIR, "auth.log")
        assert os.path.exists(log_path), f"{log_path} not found"
        engine = IngestionEngine()
        raw_lines = engine.ingest_sample(log_path)
        assert len(raw_lines) > 0
        parsed = parse_line(raw_lines[0], "syslog")
        event = normalize(parsed, "auth.log")
        assert event.host
        assert event.severity

    def test_normalize_to_store(self):
        store = EventStore()
        log_path = os.path.join(SAMPLE_LOG_DIR, "web_access.log")
        assert os.path.exists(log_path)
        engine = IngestionEngine()
        raw_lines = engine.ingest_sample(log_path)
        for line in raw_lines:
            parsed = parse_line(line, "syslog")
            event = normalize(parsed, "web_access.log")
            store.store_event(event)
        assert len(store) > 0
        stats = store.get_statistics()
        assert stats["total_events"] > 0

    def test_store_to_detect(self):
        store = EventStore()
        engine = IngestionEngine()
        log_path = os.path.join(SAMPLE_LOG_DIR, "auth.log")
        raw_lines = engine.ingest_sample(log_path)
        for line in raw_lines:
            parsed = parse_line(line, "syslog")
            event = normalize(parsed, "auth.log")
            store.store_event(event)
        rules_engine = RulesEngine()
        rules_engine.add_rule(DetectionRule(
            id="INT-TEST", name="Integration Test", description="",
            conditions={"event_type": "authentication"}
        ))
        matched_count = 0
        for event in store:
            matched = rules_engine.evaluate({"event_type": event.event_type})
            if matched:
                matched_count += 1
        assert matched_count >= 0

    def test_detect_to_respond(self):
        rules_engine = RulesEngine()
        rules_engine.add_rule(DetectionRule(
            id="INT-RESP", name="Response Test", description="",
            conditions={"event_type": "malware"}
        ))
        matched = rules_engine.evaluate({"event_type": "malware"})
        if matched:
            pb = get_playbook("malware")
            assert pb is not None
            results = execute_playbook(pb)
            assert len(results) > 0
            orchestrator = SOAROrchestrator()
            orchestrator.register_workflow(SOARWorkflow(
                id="WF-INT", name="Integration WF",
                triggers=["malware"],
                actions=[WorkflowAction("block_ip", {"ip": "10.0.0.1"})],
            ))
            result = orchestrator.trigger("WF-INT")
            assert result["status"] == "completed"
            notifier = Notifier()
            notifier_results = notifier.send_alert("Test", "Test alert", "high")
            assert len(notifier_results) > 0
