from dataclasses import dataclass
from typing import Any


@dataclass
class Control:
    id: str
    name: str
    framework: str
    category: str
    description: str


NIST_CSF_CONTROLS = [
    Control("NIST-ID-1", "Risk Assessment", "NIST CSF 2.0", "Identify", "Identify and document risks"),
    Control("NIST-ID-2", "Asset Management", "NIST CSF 2.0", "Identify", "Maintain asset inventory"),
    Control("NIST-PR-1", "Access Control", "NIST CSF 2.0", "Protect", "Manage access to assets"),
    Control("NIST-PR-2", "Data Security", "NIST CSF 2.0", "Protect", "Protect data at rest and transit"),
    Control("NIST-DE-1", "Anomalies and Events", "NIST CSF 2.0", "Detect", "Detect security events"),
    Control("NIST-DE-2", "Continuous Monitoring", "NIST CSF 2.0", "Detect", "Implement continuous monitoring"),
    Control("NIST-RS-1", "Response Planning", "NIST CSF 2.0", "Respond", "Execute incident response plan"),
    Control("NIST-RC-1", "Recovery Planning", "NIST CSF 2.0", "Recover", "Implement recovery procedures"),
]

ISO_CONTROLS = [
    Control("ISO-A.5.1", "Information Security Policy", "ISO 27001:2022", "Policies", "Define security policy"),
    Control("ISO-A.6.2", "Mobile Devices", "ISO 27001:2022", "Access", "Secure mobile device access"),
    Control("ISO-A.8.1", "Asset Inventory", "ISO 27001:2022", "Assets", "Maintain asset register"),
    Control("ISO-A.8.2", "Information Classification", "ISO 27001:2022", "Assets", "Classify information assets"),
    Control("ISO-A.8.12", "Data Leakage", "ISO 27001:2022", "Assets", "Prevent data leakage"),
    Control("ISO-A.8.16", "Monitoring", "ISO 27001:2022", "Assets", "Monitor system usage"),
]

PCI_CONTROLS = [
    Control("PCI-1.1", "Firewall Configuration", "PCI DSS v4.0", "Network", "Configure firewall rules"),
    Control("PCI-2.1", "Vendor Defaults", "PCI DSS v4.0", "Config", "Change vendor defaults"),
    Control("PCI-3.1", "Data Protection", "PCI DSS v4.0", "Data", "Protect stored cardholder data"),
    Control("PCI-7.1", "Access Control", "PCI DSS v4.0", "Access", "Restrict access by business need"),
    Control("PCI-10.1", "Audit Trails", "PCI DSS v4.0", "Audit", "Implement audit trails"),
    Control("PCI-11.1", "Vulnerability Scanning", "PCI DSS v4.0", "Security", "Run vulnerability scans"),
]

BI_POJK_CONTROLS = [
    Control("POJK-3.1", "IT Risk Management", "BI/POJK No. 11", "Risk", "Implement IT risk management"),
    Control("POJK-4.1", "IT Continuity", "BI/POJK No. 11", "BCP", "Maintain business continuity plan"),
    Control("POJK-5.1", "Outsourcing Security", "BI/POJK No. 11", "Vendor", "Manage third-party risk"),
    Control("POJK-6.1", "Data Protection", "BI/POJK No. 11", "Data", "Protect customer financial data"),
]

ALL_FRAMEWORKS = {
    "NIST CSF 2.0": NIST_CSF_CONTROLS,
    "ISO 27001:2022": ISO_CONTROLS,
    "PCI DSS v4.0": PCI_CONTROLS,
    "BI/POJK No. 11": BI_POJK_CONTROLS,
}


def get_frameworks() -> dict[str, list[Control]]:
    return dict(ALL_FRAMEWORKS)


def get_controls_by_framework(framework: str) -> list[Control]:
    return ALL_FRAMEWORKS.get(framework, [])


CROSS_MAPPINGS: dict[tuple[str, str], list[tuple[str, str]]] = {
    ("NIST CSF 2.0", "ISO 27001:2022"): [
        ("NIST-ID-1", "ISO-A.5.1"), ("NIST-ID-2", "ISO-A.8.1"),
        ("NIST-PR-1", "ISO-A.6.2"), ("NIST-PR-2", "ISO-A.8.12"),
        ("NIST-DE-1", "ISO-A.8.16"), ("NIST-DE-2", "ISO-A.8.16"),
    ],
    ("NIST CSF 2.0", "PCI DSS v4.0"): [
        ("NIST-ID-1", "PCI-11.1"), ("NIST-PR-1", "PCI-7.1"),
        ("NIST-PR-2", "PCI-3.1"), ("NIST-DE-1", "PCI-10.1"),
    ],
}


def map_controls(source_framework: str, target_framework: str) -> list[dict]:
    source_controls = ALL_FRAMEWORKS.get(source_framework, [])
    target_controls = ALL_FRAMEWORKS.get(target_framework, [])
    source_map = {c.id: c for c in source_controls}
    target_map = {c.id: c for c in target_controls}
    mappings = CROSS_MAPPINGS.get((source_framework, target_framework), [])
    results = []
    for src_id, tgt_id in mappings:
        sc = source_map.get(src_id)
        tc = target_map.get(tgt_id)
        if sc and tc:
            results.append({
                "source": sc.id,
                "source_name": sc.name,
                "target": tc.id,
                "target_name": tc.name,
                "mapping_score": 0.8,
            })
    return results
