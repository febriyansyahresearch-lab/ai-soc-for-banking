import ipaddress
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class NormalizedEvent:
    timestamp: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    event_type: str = ""
    severity: str = "low"
    raw: str = ""
    source: str = ""
    host: str = ""
    message: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "host": self.host,
            "message": self.message,
            "tags": self.tags,
        }


SEVERITY_MAP = {
    "emerg": "critical", "alert": "critical", "crit": "critical",
    "err": "high", "error": "high",
    "warning": "medium", "warn": "medium",
    "notice": "low", "info": "low", "debug": "low",
}


def normalize(raw_event: dict, source: str = "") -> NormalizedEvent:
    ts = raw_event.get("timestamp", datetime.now().isoformat())
    raw_sev = raw_event.get("severity", "info").lower()
    sev = SEVERITY_MAP.get(raw_sev, "low")
    msg = raw_event.get("message") or raw_event.get("raw", "")
    return NormalizedEvent(
        timestamp=ts,
        source_ip=raw_event.get("source_ip", ""),
        dest_ip=raw_event.get("dest_ip", ""),
        event_type=raw_event.get("event_type", "unknown"),
        severity=sev,
        raw=raw_event.get("raw", ""),
        source=source,
        host=raw_event.get("host", ""),
        message=str(msg),
    )


def enrich_event(event: NormalizedEvent, lookup: dict | None = None) -> NormalizedEvent:
    if lookup is None:
        lookup = {}
    if event.source_ip in lookup:
        enrichment = lookup[event.source_ip]
        event.tags.append(enrichment.get("tag", "enriched"))
    if event.source_ip and _is_private_ip(event.source_ip):
        event.tags.append("internal")
    else:
        event.tags.append("external")
    return event


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def validate_event(event: NormalizedEvent) -> bool:
    if not event.timestamp:
        return False
    if not event.event_type:
        return False
    return True
