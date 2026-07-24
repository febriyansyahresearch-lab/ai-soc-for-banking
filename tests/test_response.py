import pytest
from src.response.playbooks import (
    get_playbook, execute_playbook, Playbook, PlaybookStep,
    MALWARE_PLAYBOOK, PHISHING_PLAYBOOK, RANSOMWARE_PLAYBOOK, DATA_BREACH_PLAYBOOK,
)
from src.response.soarch import SOAROrchestrator, SOARWorkflow, WorkflowAction, BUILTIN_WORKFLOWS
from src.response.notifications import Notifier, Alert


class TestPlaybooks:
    def test_get_malware_playbook(self):
        pb = get_playbook("malware")
        assert pb is not None
        assert pb.id == "PB-MAL-001"

    def test_get_phishing_playbook(self):
        pb = get_playbook("phishing")
        assert pb is not None
        assert pb.incident_type == "phishing"

    def test_get_unknown_playbook(self):
        pb = get_playbook("unknown")
        assert pb is None

    def test_malware_has_steps(self):
        assert len(MALWARE_PLAYBOOK.steps) == 12

    def test_ransomware_has_steps(self):
        assert len(RANSOMWARE_PLAYBOOK.steps) == 12

    def test_execute_playbook(self):
        results = execute_playbook(MALWARE_PLAYBOOK)
        assert len(results) == len(MALWARE_PLAYBOOK.steps)
        for r in results:
            assert r["status"] == "completed"

    def test_all_playbooks_defined(self):
        for incident_type in ("malware", "phishing", "ransomware", "data_breach"):
            pb = get_playbook(incident_type)
            assert pb is not None
            assert len(pb.steps) >= 8


class TestSOAR:
    def test_register_workflow(self):
        orchestrator = SOAROrchestrator()
        wf = SOARWorkflow(id="WF-TEST", name="Test", triggers=["test"])
        orchestrator.register_workflow(wf)
        assert len(orchestrator.get_workflows()) == 1

    def test_trigger_existing(self):
        orchestrator = SOAROrchestrator()
        wf = SOARWorkflow(id="WF-TEST", name="Test", triggers=["test"], actions=[WorkflowAction("test_action", {})])
        orchestrator.register_workflow(wf)
        result = orchestrator.trigger("WF-TEST", {"test": "data"})
        assert result["status"] == "completed"

    def test_trigger_nonexistent(self):
        orchestrator = SOAROrchestrator()
        result = orchestrator.trigger("WF-NONE")
        assert result["status"] == "error"

    def test_builtin_workflows(self):
        assert len(BUILTIN_WORKFLOWS) == 3
        for wf in BUILTIN_WORKFLOWS:
            assert len(wf.actions) >= 2

    def test_execution_log(self):
        orchestrator = SOAROrchestrator()
        wf = SOARWorkflow(id="WF-TEST", name="Test", triggers=["test"])
        orchestrator.register_workflow(wf)
        orchestrator.trigger("WF-TEST")
        log = orchestrator.get_execution_log()
        assert len(log) == 1


class TestNotifications:
    def test_send_default_channel(self):
        notifier = Notifier()
        results = notifier.send_alert("Test Alert", "This is a test", "high")
        assert len(results) >= 1
        assert results[0]["status"] == "sent"

    def test_add_channel(self):
        notifier = Notifier()
        notifier.add_channel("email", {"enabled": True})
        assert "email" in notifier._channels

    def test_send_multiple_channels(self):
        notifier = Notifier()
        notifier.add_channel("console")
        notifier.add_channel("slack", {"enabled": False})
        results = notifier.send_alert("Test", "msg", "low")
        assert len(results) == 1

    def test_create_incident_ticket(self):
        notifier = Notifier()
        ticket = notifier.create_incident_ticket({"title": "Test Incident", "severity": "high"})
        assert ticket["status"] == "open"
        assert ticket["severity"] == "high"

    def test_alert_default_timestamp(self):
        alert = Alert(title="Test", message="Test", severity="low")
        assert alert.timestamp
