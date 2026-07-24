import pytest
from src.compliance.frameworks import get_frameworks, get_controls_by_framework, map_controls
from src.compliance.reporting import ComplianceReport, ComplianceGap


class TestFrameworks:
    def test_get_frameworks(self):
        frameworks = get_frameworks()
        assert "NIST CSF 2.0" in frameworks
        assert "ISO 27001:2022" in frameworks
        assert "PCI DSS v4.0" in frameworks
        assert "BI/POJK No. 11" in frameworks

    def test_get_nist_controls(self):
        controls = get_controls_by_framework("NIST CSF 2.0")
        assert len(controls) == 8
        assert controls[0].framework == "NIST CSF 2.0"

    def test_get_iso_controls(self):
        controls = get_controls_by_framework("ISO 27001:2022")
        assert len(controls) == 6

    def test_get_pci_controls(self):
        controls = get_controls_by_framework("PCI DSS v4.0")
        assert len(controls) == 6

    def test_get_bi_pojk_controls(self):
        controls = get_controls_by_framework("BI/POJK No. 11")
        assert len(controls) == 4

    def test_map_controls(self):
        mappings = map_controls("NIST CSF 2.0", "ISO 27001:2022")
        assert len(mappings) >= 1
        for m in mappings:
            assert "source" in m
            assert "target" in m

    def test_unknown_framework(self):
        controls = get_controls_by_framework("Unknown")
        assert controls == []


class TestComplianceReport:
    def test_generate_status_empty(self):
        report = ComplianceReport()
        status = report.generate_status("NIST CSF 2.0")
        assert status["compliance_pct"] == 0.0

    def test_generate_status_full(self):
        report = ComplianceReport()
        for control in get_controls_by_framework("NIST CSF 2.0"):
            report.mark_implemented("NIST CSF 2.0", control.id)
        status = report.generate_status("NIST CSF 2.0")
        assert status["compliance_pct"] == 100.0

    def test_generate_status_partial(self):
        report = ComplianceReport()
        controls = get_controls_by_framework("NIST CSF 2.0")
        report.mark_implemented("NIST CSF 2.0", controls[0].id)
        report.mark_implemented("NIST CSF 2.0", controls[1].id)
        status = report.generate_status("NIST CSF 2.0")
        assert status["implemented"] == 2

    def test_gap_analysis(self):
        report = ComplianceReport()
        report.mark_implemented("NIST CSF 2.0", "NIST-ID-1")
        gaps = report.get_gap_analysis("NIST CSF 2.0")
        assert len(gaps) == len(get_controls_by_framework("NIST CSF 2.0")) - 1
        for g in gaps:
            assert g.status == "not_implemented"

    def test_gap_analysis_all_frameworks(self):
        report = ComplianceReport()
        gaps = report.get_gap_analysis()
        total = sum(len(c) for c in get_frameworks().values())
        assert len(gaps) == total

    def test_report_markdown(self):
        report = ComplianceReport()
        markdown = report.generate_compliance_report()
        assert "Compliance Report" in markdown
        assert "NIST CSF 2.0" in markdown
