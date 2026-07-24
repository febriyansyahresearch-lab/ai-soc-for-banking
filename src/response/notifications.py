from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Alert:
    title: str
    message: str
    severity: str
    source: str = "ai-soc"
    timestamp: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class Notifier:
    def __init__(self):
        self._channels: dict[str, dict] = {}

    def add_channel(self, name: str, config: dict | None = None) -> None:
        if config is None:
            config = {"enabled": True, "type": name}
        self._channels[name] = config

    def remove_channel(self, name: str) -> bool:
        return bool(self._channels.pop(name, None))

    def send_alert(self, title: str, message: str, severity: str = "medium") -> list[dict]:
        if not self._channels:
            self.add_channel("console")
        results = []
        for name, config in self._channels.items():
            if not config.get("enabled", True):
                continue
            result = {
                "channel": name,
                "status": "sent",
                "alert": title,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
            }
            results.append(result)
        return results

    def create_incident_ticket(self, alert_data: dict) -> dict:
        ticket = {
            "ticket_id": f"TKT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "title": alert_data.get("title", "Incident"),
            "severity": alert_data.get("severity", "medium"),
            "status": "open",
            "created_at": datetime.now().isoformat(),
            "assigned_to": "soc-team",
        }
        return ticket
