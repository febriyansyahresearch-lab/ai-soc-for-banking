# AI-SOC for Banking — AI-Powered Security Operations Center

[![CI](https://github.com/febriyansyahresearch-lab/ai-soc-for-banking/actions/workflows/test.yml/badge.svg)](https://github.com/febriyansyahresearch-lab/ai-soc-for-banking/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Febriyansyah** — IT Cybersecurity & Infrastructure Leader (15+ yrs, Banking) | MTI Candidate

---

## Problem Statement

Regional banks and financial institutions lack affordable Security Operations Center (SOC) capabilities. Commercial SIEM/SOAR solutions are prohibitively expensive, and open-source alternatives require significant integration effort. This framework provides an end-to-end AI-powered SOC tailored for banking environments.

## Methodology

### Architecture

1. **SIEM-Lite** — Multi-format log ingestion (syslog, JSON, CSV), normalization to common schema, in-memory event store with query and filtering.
2. **Detection** — Three-layer detection: rule-based (Sigma-like), statistical anomaly (z-score/rolling average), and event correlation with time windows.
3. **Response** — Automated IR playbooks (NIST 800-61 aligned), SOAR workflow orchestration (TheHive integration, ticket creation, blocking), multi-channel notifications.
4. **Compliance** — Control framework mappings (NIST CSF 2.0, ISO 27001, PCI DSS, BI/POJK) and automated compliance reporting.
5. **Dashboard** — Streamlit-based multi-page web interface for real-time monitoring, incident management, compliance tracking, and configuration.

### Pipeline

```
Log Sources → Ingestion → Parsing → Normalization → Storage
                                                     ↓
Rules Engine ← Anomaly Detection ← Correlation Engine
      ↓                    ↓                    ↓
              SOAR Orchestration
              ↓           ↓           ↓
         Playbooks   Notifications  Dashboard
```

## Key Concepts

| Concept | Description |
|---|---|
| SIEM-Lite | Lightweight log ingestion and event management |
| Detection Rules | Sigma-style event matching conditions |
| Anomaly Score | Statistical deviation from baseline (0-1) |
| Correlation Window | Time-based multi-event correlation |
| SOAR Workflow | Automated response with conditional branching |
| GRC Mapping | Cross-framework control mapping for compliance |

## Repository Structure

```
ai-soc-for-banking/
├── src/
│   ├── siem/          # Log ingestion, parsing, normalization, storage
│   ├── detection/     # Rules engine, anomaly detection, correlation
│   ├── response/      # IR playbooks, SOAR orchestration, notifications
│   ├── compliance/    # Control frameworks, compliance reporting
│   └── dashboard/     # Streamlit web interface (multi-page)
├── data/sample_logs/  # Synthetic log samples for testing
├── tests/             # Unit and integration tests
├── .github/           # CI pipeline
└── README.md
```

## Getting Started

```bash
# Clone
git clone https://github.com/febriyansyahresearch-lab/ai-soc-for-banking.git
cd ai-soc-for-banking

# Setup
python -m venv venv
source venv/bin/activate   # Linux/Mac
# .\venv\Scripts\activate  # Windows
pip install -r requirements.txt

# Run tests
python -m pytest tests/ -v
```

## Dashboard

```bash
streamlit run src/dashboard/app.py
```

### Dashboard Preview

| View | What it shows |
|---|---|
| SOC Overview | Event volume, alert severity, open incidents, and response status |
| Detection | Rule matches, anomaly scores, and correlated incident chains |
| Incident Response | NIST-aligned playbook steps and SOAR execution logs |
| Compliance | NIST CSF, ISO 27001, PCI DSS, and BI/POJK control coverage |

## Quick Demo

```bash
python -m pytest tests/ -q
streamlit run src/dashboard/app.py
```

Example validation output:

```text
68 passed
```

## References

- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide
- NIST Cybersecurity Framework 2.0
- ISO/IEC 27001:2022
- PCI DSS v4.0
- POJK No. 11/POJK.03/2022 — Indonesian banking IT risk management
- MITRE ATT&CK Framework
