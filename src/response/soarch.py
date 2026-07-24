from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable


@dataclass
class WorkflowAction:
    type: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class SOARWorkflow:
    id: str
    name: str
    triggers: list[str]
    actions: list[WorkflowAction] = field(default_factory=list)


class SOAROrchestrator:
    def __init__(self):
        self._workflows: dict[str, SOARWorkflow] = {}
        self._execution_log: list[dict] = []

    def register_workflow(self, workflow: SOARWorkflow) -> None:
        self._workflows[workflow.id] = workflow

    def get_workflows(self) -> list[SOARWorkflow]:
        return list(self._workflows.values())

    def trigger(self, workflow_id: str, context: dict | None = None) -> dict:
        if context is None:
            context = {}
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return {"status": "error", "message": f"Workflow {workflow_id} not found"}
        results = []
        for action in workflow.actions:
            result = self._execute_action(action, context)
            results.append(result)
        log_entry = {
            "workflow_id": workflow_id,
            "workflow_name": workflow.name,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "status": "completed",
        }
        self._execution_log.append(log_entry)
        return log_entry

    def _execute_action(self, action: WorkflowAction, context: dict) -> dict:
        base_result = {"action_type": action.type, "params": action.params, "status": "executed"}
        return base_result

    def get_execution_log(self) -> list[dict]:
        return list(self._execution_log)


BUILTIN_WORKFLOWS = [
    SOARWorkflow(
        id="WF-MALWARE",
        name="Malware Auto-Contain",
        triggers=["malware_alert", "malware_detected"],
        actions=[
            WorkflowAction("thehive_create_case", {"title": "Malware Incident - {host}", "severity": "high"}),
            WorkflowAction("block_ip", {"ip": "{source_ip}", "duration": "24h"}),
            WorkflowAction("send_email", {"to": "soc@bank.local", "subject": "Malware Alert: {host}"}),
            WorkflowAction("create_ticket", {"system": "servicenow", "priority": "high"}),
        ],
    ),
    SOARWorkflow(
        id="WF-PHISHING",
        name="Phishing Auto-Response",
        triggers=["phishing_alert", "phishing_reported"],
        actions=[
            WorkflowAction("thehive_create_case", {"title": "Phishing Incident - {reporter}", "severity": "medium"}),
            WorkflowAction("remove_email", {"sender": "{sender}", "mailbox": "all"}),
            WorkflowAction("create_ticket", {"system": "servicenow", "priority": "medium"}),
        ],
    ),
    SOARWorkflow(
        id="WF-BRUTEFORCE",
        name="Brute Force Auto-Block",
        triggers=["bruteforce_alert", "multiple_failed_logins"],
        actions=[
            WorkflowAction("block_ip", {"ip": "{source_ip}", "duration": "48h"}),
            WorkflowAction("send_email", {"to": "soc@bank.local", "subject": "Brute Force Blocked: {source_ip}"}),
            WorkflowAction("create_ticket", {"system": "servicenow", "priority": "high"}),
        ],
    ),
]
