import streamlit as st


def show() -> None:
    st.title("Settings")
    st.subheader("Detection Rules")
    rules = [
        {"name": "Multiple Failed Logins", "enabled": True, "severity": "High"},
        {"name": "High-Risk Country", "enabled": True, "severity": "High"},
        {"name": "Unusual Port Access", "enabled": False, "severity": "Medium"},
        {"name": "Malicious Hash", "enabled": True, "severity": "Critical"},
        {"name": "Privilege Escalation", "enabled": True, "severity": "High"},
    ]
    for rule in rules:
        col1, col2, col3 = st.columns([3, 1, 1])
        col1.text(rule["name"])
        col2.text(rule["severity"])
        col3.checkbox("Enabled", value=rule["enabled"], key=rule["name"])
    st.subheader("Notification Channels")
    channels = [
        {"name": "Console", "enabled": True},
        {"name": "Email", "enabled": False},
        {"name": "Slack", "enabled": False},
        {"name": "TheHive", "enabled": True},
    ]
    for ch in channels:
        col1, col2 = st.columns([3, 1])
        col1.text(ch["name"])
        col2.checkbox("Active", value=ch["enabled"], key=f"ch_{ch['name']}")
    st.subheader("SOC Metrics Thresholds")
    st.slider("Alert Severity Threshold", 1, 10, 5)
    st.slider("Auto-Contain Severity", 1, 10, 8)
    st.number_input("Max Events per Source (per min)", value=1000)
