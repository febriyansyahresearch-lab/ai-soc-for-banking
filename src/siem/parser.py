import json
import re
from datetime import datetime


SYSLOG_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<message>.*)"
)


def parse_syslog(line: str) -> dict:
    m = SYSLOG_PATTERN.match(line)
    if not m:
        return {"raw": line, "event_type": "unknown"}
    parts = m.groupdict()
    facility_map = {"auth": "authentication", "kern": "kernel", "user": "user"}
    for key, val in facility_map.items():
        if key in parts.get("message", "").lower():
            parts["event_type"] = val
            break
    else:
        parts["event_type"] = "system"
    parts["raw"] = line
    return parts


def parse_json_log(line: str) -> dict:
    try:
        data = json.loads(line)
        return data
    except json.JSONDecodeError:
        return {"raw": line, "event_type": "unknown"}


def parse_csv_log(line: str, headers: list[str] | None = None) -> dict:
    if headers is None:
        headers = ["timestamp", "source_ip", "dest_ip", "event_type", "severity", "message"]
    fields = line.strip().split(",")
    result = {}
    for i, h in enumerate(headers):
        result[h] = fields[i] if i < len(fields) else ""
    result["raw"] = line
    return result


def parse_line(line: str, format_hint: str = "syslog") -> dict:
    parsers = {
        "syslog": parse_syslog,
        "json": parse_json_log,
        "csv": parse_csv_log,
    }
    parser = parsers.get(format_hint, parse_syslog)
    return parser(line)
