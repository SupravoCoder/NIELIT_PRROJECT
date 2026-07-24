import os
import requests
import streamlit as st



# Configure Streamlit page layout
st.set_page_config(
    page_title="VulnSense AI — Security Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000/api/v1")

# Cyber Security Theme CSS
CUSTOM_CSS = """
<style>
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: 'Inter', system-ui, sans-serif;
    }
    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #1e293b;
    }
    div[data-testid="stMetricValue"] {
        font-size: 2.2rem !important;
        font-weight: 800 !important;
        color: #38bdf8 !important;
    }
    .header-title {
        background: linear-gradient(90deg, #38bdf8 0%, #818cf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        font-size: 2.4rem;
        margin-bottom: 0.2rem;
    }
    .status-online {
        color: #4ade80;
        background: rgba(74, 222, 128, 0.1);
        padding: 4px 12px;
        border-radius: 9999px;
        border: 1px solid rgba(74, 222, 128, 0.3);
        font-size: 0.85rem;
        font-weight: 600;
    }
    .status-offline {
        color: #f87171;
        background: rgba(248, 113, 113, 0.1);
        padding: 4px 12px;
        border-radius: 9999px;
        border: 1px solid rgba(248, 113, 113, 0.3);
        font-size: 0.85rem;
        font-weight: 600;
    }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def check_backend_health() -> bool:
    """Verify backend connectivity to FastAPI server."""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=3)
        return response.status_code == 200 and response.json().get("status") == "ok"
    except Exception:
        return False


def render_sidebar():
    """Render sidebar navigation and health indicator."""
    st.sidebar.markdown("### 🛡️ VulnSense AI")
    st.sidebar.caption("Automated Risk Prioritization & Remediation")
    st.sidebar.divider()

    backend_ok = check_backend_health()
    if backend_ok:
        st.sidebar.markdown('<span class="status-online">● Backend Online</span>', unsafe_allow_html=True)
    else:
        st.sidebar.markdown('<span class="status-offline">○ Backend Disconnected</span>', unsafe_allow_html=True)

    st.sidebar.write("")
    nav_option = st.sidebar.radio(
        "Navigation",
        options=[
            "📊 Dashboard Overview",
            "🔍 Execute Security Scan",
            "⚡ Vulnerability Explorer",
            "📑 Export Reports",
        ],
    )
    st.sidebar.divider()
    st.sidebar.caption("Version 0.1.0 | Industry & Research Grade")
    return nav_option, backend_ok


def render_overview():
    """Render dashboard summary metrics."""
    st.markdown('<div class="header-title">Security Posture Dashboard</div>', unsafe_allow_html=True)
    st.caption("Real-time summary of target network scans, vulnerabilities detected, and CVSS risk scores.")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Total Scans Executed", value=st.session_state.get("scan_count", 0))
    with col2:
        st.metric(label="Services Analyzed", value=st.session_state.get("services_count", 0))
    with col3:
        st.metric(label="CVEs Identified", value=st.session_state.get("cve_count", 0))
    with col4:
        st.metric(label="Max CVSS Score", value=st.session_state.get("max_cvss", 0.0))

    st.divider()
    st.subheader("Automated Security Pipeline Workflow")
    st.info(
        "**Target Input** ➔ **Nmap Service Scan** ➔ **Software Version Normalization** ➔ "
        "**NVD CVE Database Search** ➔ **CVSS Risk Scoring** ➔ **LLM Remediation Guidance** ➔ **HTML Report Generation**"
    )


def render_scan_page():
    """Render interactive scan launcher and result viewer."""
    st.markdown('<div class="header-title">Initiate Vulnerability Scan</div>', unsafe_allow_html=True)
    st.caption("Enter a target IP or domain to execute automated service discovery and CVE risk analysis.")

    with st.form("scan_form"):
        col1, col2 = st.columns([3, 1])
        with col1:
            target_ip = st.text_input("Target IP Address / Domain", value="192.168.1.10", help="e.g., 127.0.0.1 or 192.168.1.10")
        with col2:
            scan_args = st.selectbox("Scan Profile", options=["-sV -T4 -F (Fast Version Scan)", "-sV -T4 (Standard Port Scan)"])

        use_mock = st.checkbox("Enable Simulated Fallback Mode (Recommended if Nmap binary absent)", value=True)
        submit_button = st.form_submit_button("🚀 Start Vulnerability Assessment", use_container_width=True)



    if submit_button:
        with st.spinner(f"Scanning target '{target_ip}' and querying NVD CVE database..."):
            try:
                payload = {
                    "target": target_ip,
                    "scan_arguments": scan_args.split()[0],
                    "use_mock_fallback": use_mock,
                }
                resp = requests.post(f"{API_BASE_URL}/scan", json=payload, timeout=15)
                if resp.status_code == 200:
                    summary_data = resp.json()
                    st.session_state["last_scan"] = summary_data
                    st.session_state["scan_count"] = st.session_state.get("scan_count", 0) + 1
                    st.session_state["services_count"] = summary_data.get("total_services_scanned", 0)
                    st.session_state["cve_count"] = summary_data.get("total_vulnerabilities_found", 0)
                    st.session_state["max_cvss"] = summary_data.get("max_cvss_score", 0.0)
                    st.success("✅ Assessment Completed Successfully!")
                else:
                    st.error(f"Scan failed with server error: {resp.text}")
            except Exception as e:
                st.error(f"Failed to communicate with backend service: {e}")

    # Display Scan Results if present
    if "last_scan" in st.session_state:
        scan = st.session_state["last_scan"]
        st.divider()
        st.subheader(f"Results for Target: {scan['target']}")
        st.caption(f"Scan ID: {scan['scan_id']}")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Services Scanned", scan["total_services_scanned"])
        m2.metric("Vulnerabilities Found", scan["total_vulnerabilities_found"])
        m3.metric("Max CVSS Score", scan["max_cvss_score"])
        m4.metric("Status", "Complete")

        st.subheader("Severity Breakdown")
        dist = scan.get("risk_distribution", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.error(f"Critical: {dist.get('CRITICAL', 0)}")
        c2.warning(f"High: {dist.get('HIGH', 0)}")
        c3.info(f"Medium: {dist.get('MEDIUM', 0)}")
        c4.success(f"Low/Info: {dist.get('LOW', 0) + dist.get('INFO', 0)}")

        st.subheader("Prioritized Vulnerability Matrix")
        findings = scan.get("findings", [])
        if findings:
            for f in findings:
                with st.expander(f"⚠️ [{f['severity']}] {f['cve']['cve_id']} — {f['product']} {f['version']} (Port {f['port']}) — Risk Score: {f['risk_score']}"):
                    st.write(f"**Description**: {f['cve']['description']}")
                    st.write(f"**AI Plain Language Explanation**: {f.get('llm_explanation', 'N/A')}")
                    st.write(f"**Remediation & Patch Guidance**: {f.get('remediation_guidance', 'N/A')}")
                    if f['cve'].get('references'):
                        st.markdown(f"**Reference Link**: [{f['cve']['references'][0]}]({f['cve']['references'][0]})")
        else:
            st.info("No vulnerabilities detected for the scanned host.")


def render_reports_page():
    """Render report download section."""
    st.markdown('<div class="header-title">Executive & Technical Security Reports</div>', unsafe_allow_html=True)

    if "last_scan" not in st.session_state:
        st.warning("No recent scan data available. Please execute a scan first under 'Execute Security Scan'.")
        return

    summary = st.session_state["last_scan"]
    st.info(f"Report ready for Target **{summary['target']}** (Scan ID: {summary['scan_id']})")

    if st.button("📄 Generate & Download HTML Security Report"):
        try:
            resp = requests.post(f"{API_BASE_URL}/reports/html", json=summary, timeout=5)
            if resp.status_code == 200:
                st.download_button(
                    label="⬇️ Download HTML Report",
                    data=resp.content,
                    file_name=f"VulnSense_Report_{summary['target'].replace('.', '_')}.html",
                    mime="text/html",
                )
            else:
                st.error("Report generation failed on backend.")
        except Exception as e:
            st.error(f"Error fetching report: {e}")


def main():
    """Main Streamlit entrypoint."""
    nav_choice, is_connected = render_sidebar()

    if not is_connected:
        st.warning(
            "⚠️ Unable to reach FastAPI backend at `http://127.0.0.1:8000/api/v1/health`. "
            "Please start backend service: `uvicorn app.main:app --reload`"
        )

    if nav_choice == "📊 Dashboard Overview":
        render_overview()
    elif nav_choice == "🔍 Execute Security Scan":
        render_scan_page()
    elif nav_choice == "⚡ Vulnerability Explorer":
        render_scan_page()
    elif nav_choice == "📑 Export Reports":
        render_reports_page()


if __name__ == "__main__":
    main()
