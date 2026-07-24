import pytest
from src.detection.rules_engine import RulesEngine, DetectionRule, BUILTIN_RULES
from src.detection.anomaly import AnomalyDetector
from src.detection.correlation import CorrelationEngine, CorrelationRule, BUILTIN_CORRELATION_RULES


class TestRulesEngine:
    def test_load_rules(self):
        engine = RulesEngine()
        engine.load_rules(BUILTIN_RULES)
        assert len(engine.get_rules()) == 5

    def test_add_rule(self):
        engine = RulesEngine()
        rule = DetectionRule(id="TEST-001", name="Test", description="Test", conditions={"event_type": "test"})
        engine.add_rule(rule)
        assert len(engine.get_rules()) == 1

    def test_evaluate_match(self):
        engine = RulesEngine()
        engine.add_rule(DetectionRule(id="T1", name="T1", description="", conditions={"event_type": "login", "status": "failed"}))
        matched = engine.evaluate({"event_type": "login", "status": "failed"})
        assert "T1" in matched

    def test_evaluate_no_match(self):
        engine = RulesEngine()
        engine.add_rule(DetectionRule(id="T1", name="T1", description="", conditions={"event_type": "login", "status": "failed"}))
        matched = engine.evaluate({"event_type": "login", "status": "success"})
        assert "T1" not in matched

    def test_builtin_rules_have_ids(self):
        for rule in BUILTIN_RULES:
            assert rule.id


class TestAnomalyDetector:
    def test_train_and_detect(self):
        detector = AnomalyDetector()
        events = [{"value": 10}, {"value": 12}, {"value": 11}, {"value": 9}, {"value": 13}]
        detector.train(events)
        score = detector.detect({"value": 100})
        assert score > 0.5

    def test_detect_without_train(self):
        detector = AnomalyDetector()
        score = detector.detect({"value": 100})
        assert score == 0.0

    def test_threshold(self):
        detector = AnomalyDetector()
        assert detector.get_threshold() == 2.0
        detector.set_threshold(3.0)
        assert detector.get_threshold() == 3.0

    def test_is_anomalous(self):
        detector = AnomalyDetector()
        events = [{"value": 10}, {"value": 12}, {"value": 11}]
        detector.train(events)
        assert detector.is_anomalous({"value": 100}) is False
        detector.set_threshold(0.0)
        assert detector.is_anomalous({"value": 100}) is True

    def test_extract_value_none(self):
        detector = AnomalyDetector()
        score = detector.detect({"no_value": "test"})
        assert score == 0.0


class TestCorrelation:
    def test_add_rule(self):
        engine = CorrelationEngine()
        engine.add_rule(BUILTIN_CORRELATION_RULES[0])
        assert len(engine.get_rules()) == 1

    def test_evaluate_no_match(self):
        engine = CorrelationEngine()
        engine.add_rule(CorrelationRule(id="C1", name="C1", conditions=[{"a": "1"}, {"b": "2"}]))
        engine.add_event({"a": "1"})
        incidents = engine.evaluate()
        assert len(incidents) == 0

    def test_evaluate_match(self):
        engine = CorrelationEngine()
        engine.add_rule(CorrelationRule(id="C1", name="C1", conditions=[{"event_type": "scan"}, {"event_type": "failed_auth"}]))
        engine.add_event({"id": "e1", "event_type": "scan"})
        engine.add_event({"id": "e2", "event_type": "failed_auth"})
        incidents = engine.evaluate()
        assert len(incidents) == 1
        assert incidents[0].rule_id == "C1"

    def test_builtin_rules_have_ids(self):
        for rule in BUILTIN_CORRELATION_RULES:
            assert rule.id
            assert len(rule.conditions) >= 2

    def test_incident_dict(self):
        engine = CorrelationEngine()
        engine.add_rule(CorrelationRule(id="C1", name="C1", conditions=[{"a": "1"}, {"b": "2"}]))
        engine.add_event({"id": "e1", "a": "1"})
        engine.add_event({"id": "e2", "b": "2"})
        incidents = engine.evaluate()
        assert len(incidents) == 1
        d = incidents[0].to_dict()
        assert "rule_id" in d
        assert "severity" in d
