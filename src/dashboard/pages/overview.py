import streamlit as st
from datetime import datetime, timedelta
import random


def show() -> None:
    st.title("SOC Overview")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", "1,247", "+12.3%")
    col2.metric("Active Alerts", "3", "-2")
    col3.metric("Avg Response Time", "4.2 min", "-0.8 min")
    col4.metric("False Positive Rate", "2.1%", "-0.3%")
    st.subheader("Event Timeline (Last 24 Hours)")
    hours = list(range(24))
    values = [random.randint(30, 120) for _ in range(24)]
    chart_data = {"hour": hours, "events": values}
    st.bar_chart(chart_data, x="hour", y="events")
    st.subheader("Top Alert Types")
    alerts = [
        {"type": "Failed Login", "count": 142},
        {"type": "Port Scan", "count": 89},
        {"type": "Malware Detection", "count": 12},
        {"type": "Policy Violation", "count": 45},
    ]
    for a in alerts:
        st.text(f"{a['type']}: {a['count']}")
