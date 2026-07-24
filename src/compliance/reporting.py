from dataclasses import dataclass
from datetime import datetime

from src.compliance.frameworks import get_frameworks


@dataclass
class ComplianceGap:
    control_id: str
    control_name: str
    framework: str
    status: str
    recommendation: str = ""


class ComplianceReport:
    def __init__(self):
        self._implemented_controls: dict[str, set[str]] = {}

    def mark_implemented(self, framework: str, control_id: str) -> None:
        if framework not in self._implemented_controls:
            self._implemented_controls[framework] = set()
        self._implemented_controls[framework].add(control_id)

    def generate_status(self, framework: str) -> dict:
        frameworks = get_frameworks()
        all_controls = frameworks.get(framework, [])
        if not all_controls:
            return {"framework": framework, "compliance_pct": 0.0, "implemented": 0, "total": 0}
        implemented_set = self._implemented_controls.get(framework, set())
        implemented_count = sum(1 for c in all_controls if c.id in implemented_set)
        total = len(all_controls)
        pct = round((implemented_count / total) * 100, 1) if total > 0 else 0.0
        return {"framework": framework, "compliance_pct": pct, "implemented": implemented_count, "total": total}

    def generate_compliance_report(self) -> str:
        lines = []
        lines.append("# Compliance Report\n")
        lines.append(f"**Generated:** {datetime.now().isoformat()}\n")
        lines.append("## Framework Status\n")
        for framework in get_frameworks():
            status = self.generate_status(framework)
            bar = "█" * int(status["compliance_pct"] / 10) + "░" * (10 - int(status["compliance_pct"] / 10))
            lines.append(f"- **{framework}**: {status['compliance_pct']}% {bar} ({status['implemented']}/{status['total']})")
        lines.append("\n## Gap Analysis\n")
        for framework, controls in get_frameworks().items():
            implemented = self._implemented_controls.get(framework, set())
            gaps = [c for c in controls if c.id not in implemented]
            if gaps:
                lines.append(f"### {framework}\n")
                for g in gaps:
                    lines.append(f"- {g.id} - {g.name}")
        return "\n".join(lines)

    def get_gap_analysis(self, framework: str | None = None) -> list[ComplianceGap]:
        gaps = []
        for fw, controls in get_frameworks().items():
            if framework and fw != framework:
                continue
            implemented = self._implemented_controls.get(fw, set())
            for c in controls:
                if c.id not in implemented:
                    gaps.append(ComplianceGap(c.id, c.name, fw, "not_implemented"))
        return gaps
