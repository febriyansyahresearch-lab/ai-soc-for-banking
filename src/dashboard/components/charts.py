from dataclasses import dataclass
from typing import Any


@dataclass
class ChartComponent:
    title: str
    chart_type: str
    data: list[dict[str, Any]]

    def render(self) -> dict:
        return {
            "title": self.title,
            "chart_type": self.chart_type,
            "data": self.data,
            "description": f"{self.chart_type} chart showing {self.title}",
        }
