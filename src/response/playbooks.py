from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlaybookStep:
    phase: str
    action: str
    description: str
    assignee: str = "analyst"


@dataclass
class Playbook:
    id: str
    name: str
    incident_type: str
    severity: str
    steps: list[PlaybookStep] = field(default_factory=list)


MALWARE_PLAYBOOK = Playbook(
    id="PB-MAL-001",
    name="Malware Infection Response",
    incident_type="malware",
    severity="high",
    steps=[
        PlaybookStep("identification", "detect", "Identify and confirm malware presence", "tier1"),
        PlaybookStep("containment", "disconnect", "Isolate affected host from network", "tier2"),
        PlaybookStep("containment", "block_ioc", "Block identified IOCs at firewall", "tier2"),
        PlaybookStep("analysis", "scan", "Run full antivirus/EDR scan on affected host", "tier2"),
        PlaybookStep("analysis", "collect_sample", "Collect malware sample for forensics", "tier3"),
        PlaybookStep("analysis", "analyze_hash", "Hash analysis and threat intel lookup", "tier3"),
        PlaybookStep("eradication", "clean", "Remove malware from affected systems", "tier2"),
        PlaybookStep("eradication", "patch", "Apply necessary security patches", "tier2"),
        PlaybookStep("recovery", "restore", "Restore systems from clean backup", "tier2"),
        PlaybookStep("recovery", "verify", "Verify system integrity and monitoring", "tier1"),
        PlaybookStep("post-mortem", "report", "Generate incident report", "tier3"),
        PlaybookStep("post-mortem", "lessons", "Conduct lessons learned session", "manager"),
    ],
)

PHISHING_PLAYBOOK = Playbook(
    id="PB-PHISH-001",
    name="Phishing Incident Response",
    incident_type="phishing",
    severity="medium",
    steps=[
        PlaybookStep("identification", "verify", "Verify phishing report from user", "tier1"),
        PlaybookStep("containment", "remove_email", "Remove malicious email from all mailboxes", "tier2"),
        PlaybookStep("containment", "block_sender", "Block sender domain/IP at email gateway", "tier2"),
        PlaybookStep("analysis", "analyze_link", "Analyze embedded URLs for malicious intent", "tier3"),
        PlaybookStep("analysis", "analyze_attachment", "Scan attachments in sandbox", "tier3"),
        PlaybookStep("eradication", "password_reset", "Force password reset for affected users", "tier2"),
        PlaybookStep("eradication", "mfa_check", "Verify MFA enrollment for affected accounts", "tier1"),
        PlaybookStep("recovery", "monitor", "Monitor for credential abuse on affected accounts", "tier2"),
        PlaybookStep("post-mortem", "notify", "Notify affected users and stakeholders", "manager"),
        PlaybookStep("post-mortem", "training", "Conduct security awareness training", "manager"),
    ],
)

RANSOMWARE_PLAYBOOK = Playbook(
    id="PB-RANSOM-001",
    name="Ransomware Incident Response",
    incident_type="ransomware",
    severity="critical",
    steps=[
        PlaybookStep("identification", "confirm", "Confirm ransomware infection", "tier1"),
        PlaybookStep("containment", "disconnect_all", "Disconnect all affected systems from network", "tier2"),
        PlaybookStep("containment", "disable_accounts", "Disable compromised accounts", "tier2"),
        PlaybookStep("containment", "block_c2", "Block C2 communication at perimeter", "tier3"),
        PlaybookStep("analysis", "identify_strain", "Identify ransomware variant and encryption method", "tier3"),
        PlaybookStep("analysis", "assess_scope", "Assess scope of encryption and data exfiltration", "tier3"),
        PlaybookStep("analysis", "check_backup", "Verify backup integrity and last clean snapshot", "tier2"),
        PlaybookStep("eradication", "wipe_rebuild", "Wipe and rebuild affected systems from clean image", "tier2"),
        PlaybookStep("recovery", "restore_data", "Restore data from verified clean backups", "tier2"),
        PlaybookStep("recovery", "phase_return", "Phase affected systems back into production", "tier2"),
        PlaybookStep("post-mortem", "forensics", "Conduct full forensic investigation", "tier3"),
        PlaybookStep("post-mortem", "report_authorities", "Report to relevant authorities", "manager"),
    ],
)

DATA_BREACH_PLAYBOOK = Playbook(
    id="PB-DB-001",
    name="Data Breach Response",
    incident_type="data_breach",
    severity="critical",
    steps=[
        PlaybookStep("identification", "assess", "Assess data breach notification", "tier1"),
        PlaybookStep("containment", "stop_leak", "Stop active data exfiltration", "tier2"),
        PlaybookStep("containment", "preserve_evidence", "Preserve forensic evidence", "tier3"),
        PlaybookStep("analysis", "identify_data", "Identify type and volume of compromised data", "tier3"),
        PlaybookStep("analysis", "identify_scope", "Determine number of affected individuals", "tier3"),
        PlaybookStep("analysis", "root_cause", "Identify root cause of breach", "tier3"),
        PlaybookStep("eradication", "close_vector", "Close attack vector", "tier2"),
        PlaybookStep("recovery", "enhance_controls", "Implement enhanced security controls", "tier2"),
        PlaybookStep("post-mortem", "notify_regulator", "Notify data protection authorities", "manager"),
        PlaybookStep("post-mortem", "notify_subjects", "Notify affected data subjects", "manager"),
    ],
)

PLAYBOOKS = {
    "malware": MALWARE_PLAYBOOK,
    "phishing": PHISHING_PLAYBOOK,
    "ransomware": RANSOMWARE_PLAYBOOK,
    "data_breach": DATA_BREACH_PLAYBOOK,
}


def get_playbook(incident_type: str) -> Playbook | None:
    return PLAYBOOKS.get(incident_type.lower())


def execute_playbook(playbook: Playbook, context: dict | None = None) -> list[dict]:
    if context is None:
        context = {}
    results = []
    for step in playbook.steps:
        result = {
            "phase": step.phase,
            "action": step.action,
            "description": step.description,
            "assignee": step.assignee,
            "status": "completed",
        }
        results.append(result)
    return results
