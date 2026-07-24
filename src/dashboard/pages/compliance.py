import streamlit as st


def show() -> None:
    st.title("Compliance Status")
    frameworks = [
        {"name": "NIST CSF 2.0", "compliance": 85, "implemented": 22, "total": 26},
        {"name": "ISO 27001:2022", "compliance": 72, "implemented": 18, "total": 25},
        {"name": "PCI DSS v4.0", "compliance": 90, "implemented": 18, "total": 20},
        {"name": "BI/POJK No. 11", "compliance": 78, "implemented": 14, "total": 18},
    ]
    for fw in frameworks:
        st.subheader(fw["name"])
        st.progress(fw["compliance"] / 100)
        st.caption(f"{fw['compliance']}% ({fw['implemented']}/{fw['total']} controls implemented)")
    st.subheader("Gap Analysis")
    gaps = [
        {"control": "NIST-PR-2", "framework": "NIST CSF 2.0", "status": "Not Implemented"},
        {"control": "ISO-A.8.12", "framework": "ISO 27001:2022", "status": "Partially Implemented"},
        {"control": "POJK-5.1", "framework": "BI/POJK No. 11", "status": "Not Implemented"},
    ]
    for g in gaps:
        st.text(f"{g['control']} ({g['framework']}): {g['status']}")
