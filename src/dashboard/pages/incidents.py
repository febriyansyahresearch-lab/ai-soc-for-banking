import streamlit as st
from datetime import datetime


def show() -> None:
    st.title("Incidents")
    col1, col2 = st.columns(2)
    severity = col1.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])
    status = col2.selectbox("Status", ["All", "Open", "In Progress", "Resolved"])
    incidents = [
        {"id": "INC-001", "type": "Malware", "severity": "Critical", "status": "Open", "timestamp": "2026-07-25 08:15"},
        {"id": "INC-002", "type": "Phishing", "severity": "High", "status": "In Progress", "timestamp": "2026-07-25 07:30"},
        {"id": "INC-003", "type": "Brute Force", "severity": "High", "status": "Resolved", "timestamp": "2026-07-25 06:00"},
        {"id": "INC-004", "type": "Policy Violation", "severity": "Medium", "status": "Open", "timestamp": "2026-07-24 22:10"},
        {"id": "INC-005", "type": "Port Scan", "severity": "Low", "status": "Resolved", "timestamp": "2026-07-24 18:45"},
    ]
    filtered = incidents
    if severity != "All":
        filtered = [i for i in filtered if i["severity"] == severity]
    if status != "All":
        filtered = [i for i in filtered if i["status"] == status]
    st.dataframe(filtered)
