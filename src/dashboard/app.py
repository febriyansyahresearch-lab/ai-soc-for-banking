import streamlit as st


PAGE_NAMES = {
    "overview": "Overview",
    "incidents": "Incidents",
    "compliance": "Compliance",
    "settings": "Settings",
}


def main() -> None:
    st.set_page_config(page_title="AI-SOC Dashboard", layout="wide")
    st.sidebar.title("AI-SOC for Banking")
    st.sidebar.markdown("---")
    status = {
        "Events (24h)": "1,247",
        "Active Alerts": "3",
        "SOC Status": "✅ Operational",
    }
    for label, value in status.items():
        st.sidebar.metric(label, value)
    st.sidebar.markdown("---")
    page = st.sidebar.radio("Navigation", list(PAGE_NAMES.values()))
    if page == "Overview":
        from src.dashboard.pages.overview import show
    elif page == "Incidents":
        from src.dashboard.pages.incidents import show
    elif page == "Compliance":
        from src.dashboard.pages.compliance import show
    elif page == "Settings":
        from src.dashboard.pages.settings import show
    show()


if __name__ == "__main__":
    main()
