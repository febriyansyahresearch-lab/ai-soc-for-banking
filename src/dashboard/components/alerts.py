from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AlertComponent:
    alert_id: str
    title: str
    severity: str
    message: str
    timestamp: str = ""
    source: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def render(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp,
            "source": self.source,
        }
