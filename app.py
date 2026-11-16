
import streamlit as st
import pandas as pd
import plotly.express as px
import ipaddress
import re
from io import BytesIO
from datetime import datetime

from log_collector import collect_logs
from threat_detection import detect_threats
from incident_response import respond_to_incidents
from ai_analysis import analyze_incidents


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="Cyber Sentinel | AI SOC",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# COLORFUL SOC DESIGN
# --------------------------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Orbitron:wght@500;700&display=swap');

.stApp {
    background:
        radial-gradient(ellipse at 10% 0%, #18265a 0%, transparent 40%),
        radial-gradient(ellipse at 90% 10%, #35154d 0%, transparent 35%),
        #080d1b;
    color: #edf2ff;
    font-family: 'Inter', sans-serif;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #101a35, #17112d);
    border-right: 1px solid #29365c;
}

[data-testid="stMetric"] {
    background: linear-gradient(145deg, #172447, #21183d);
    border: 1px solid #394d82;
    border-radius: 16px;
    padding: 18px;
    box-shadow: 0 5px 22px #00000035;
}

[data-testid="stMetricLabel"] {
    color: #aebfe9 !important;
}

[data-testid="stMetricValue"] {
    color: #45e6ff !important;
    font-family: 'Orbitron', sans-serif;
}

h1, h2, h3 {
    color: #edf2ff !important;
}

.stButton button {
    background: linear-gradient(90deg, #087cf5, #8b42e8);
    color: white;
    border: 0;
    border-radius: 9px;
    font-weight: 700;
}

.stButton button:hover {
    border: 1px solid #45e6ff;
    color: white;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #34466f;
    border-radius: 12px;
}

div[data-testid="stExpander"] {
    border: 1px solid #35466e;
    border-radius: 12px;
    background: #111a31;
}

.soc-banner {
    background: linear-gradient(110deg, #152a54, #30204e, #102e48);
    border: 1px solid #5265a5;
    padding: 25px;
    border-radius: 18px;
    margin-bottom: 20px;
}

.soc-small {
    color: #8ca8d8;
    letter-spacing: 2px;
    font-size: 12px;
    font-weight: 700;
}

.soc-title {
    color: #ffffff;
    font-family: 'Orbitron', sans-serif;
    font-size: 30px;
    font-weight: 700;
    margin: 8px 0;
}

.soc-subtitle {
    color: #b6c7ee;
    font-size: 14px;
}

.status-pill {
    display: inline-block;
    padding: 6px 12px;
    background: #123d38;
    color: #5cf2bd;
    border: 1px solid #1e806a;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
}

.info-panel {
    background: linear-gradient(145deg, #172443, #1b1938);
    border: 1px solid #394c78;
    padding: 16px;
    border-radius: 14px;
    min-height: 105px;
}

.info-label {
    color: #9eb2df;
    font-size: 12px;
}

.info-value {
    color: #ffffff;
    font-size: 23px;
    font-weight: 800;
    margin-top: 8px;
}
</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def to_dataframe(data):
    if isinstance(data, pd.DataFrame):
        return data.copy()
    if isinstance(data, (list, tuple)):
        return pd.DataFrame(data)
    if isinstance(data, dict):
        return pd.DataFrame([data])
    return pd.DataFrame()


def find_ip_columns(df):
    return [
        col for col in df.columns
        if any(word in str(col).lower() for word in
               ["ip", "source", "destination", "address"])
    ]


def get_ip_addresses(df):
    found = set()

    for col in find_ip_columns(df):
        for value in df[col].dropna().astype(str):
            matches = re.findall(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                value
            )
            for address in matches:
                try:
                    ipaddress.ip_address(address)
                    found.add(address)
                except ValueError:
                    pass

    return sorted(found)


def local_ip_assessment(address):
    try:
        ip = ipaddress.ip_address(address)

        if ip.is_private:
            return "Private network IP", "Internal address; not externally reputation-checked"

        if ip.is_loopback:
            return "Loopback IP", "Local machine address"

        if ip.is_reserved:
            return "Reserved IP", "Special-purpose address"

        return "Public IP", "External reputation lookup not configured"

    except ValueError:
        return "Unknown", "Invalid IP address"


def calculate_risk(row):
    severity = str(row.get("severity", "")).upper()

    if severity == "HIGH":
        return 90
    if severity == "MEDIUM":
        return 60
    if severity == "LOW":
        return 30

    return 15


def show_data(data, empty_message):
    df = to_dataframe(data)

    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info(empty_message)


def make_pdf_report(log_count, threat_count, high_count, medium_count,
                    low_count, threat_df):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()

        content = [
            Paragraph("CYBER SENTINEL SOC", styles["Title"]),
            Paragraph("Security Incident Report", styles["Heading2"]),
            Spacer(1, 15),
            Paragraph(
                "Generated: " + datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                styles["Normal"]
            ),
            Spacer(1, 15)
        ]

        summary = [
            ["Metric", "Count"],
            ["Total Events", str(log_count)],
            ["Total Threats", str(threat_count)],
            ["High Severity", str(high_count)],
            ["Medium Severity", str(medium_count)],
            ["Low Severity", str(low_count)]
        ]

        table = Table(summary)
        table.setStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263c70")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8)
        ])

        content.append(table)
        content.append(Spacer(1, 20))
        content.append(Paragraph("Detected Threats", styles["Heading2"]))

        if not threat_df.empty:
            columns = list(threat_df.columns[:5])
            rows = [columns]
            for _, row in threat_df[columns].head(25).iterrows():
                rows.append([str(value)[:45] for value in row])

            threat_table = Table(rows, repeatRows=1)
            threat_table.setStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263c70")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 5)
            ])
            content.append(threat_table)

        doc.build(content)
        buffer.seek(0)
        return buffer

    except ImportError:
        return None


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:
    st.title("🛡️ CYBER SENTINEL")
    st.caption("NEXT-GEN SECURITY OPERATIONS")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard Overview",
            "Live Activity Feed",
            "Attack Analytics",
            "Security Event Logs",
            "Threat Investigation",
            "IP Intelligence",
            "AI Incident Analysis",
            "Incident Management",
            "Incident Response",
            "Security Reports"
        ]
    )

    st.divider()
    st.subheader("SYSTEM STATUS")
    st.success("● Monitoring Active")
    st.caption("AI Security Engine")
    st.caption("Prototype Mode")


# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

@st.cache_data(ttl=10)
def load_data():
    logs = to_dataframe(collect_logs())
    threats = to_dataframe(detect_threats(logs))
    analysis = analyze_incidents(threats)
    responses = respond_to_incidents(threats)

    return logs, threats, analysis, responses


if st.sidebar.button("🔄 Refresh Security Data"):
    st.cache_data.clear()
    st.rerun()


try:
    logs, threats, analysis, responses = load_data()

except Exception as error:
    st.error("Unable to load project data.")
    st.exception(error)
    st.stop()


# --------------------------------------------------
# PREPARE DATA
# --------------------------------------------------

total_events = len(logs)
total_threats = len(threats)

severity_counts = pd.Series(dtype=int)

if not threats.empty and "severity" in threats.columns:
    severity_counts = (
        threats["severity"].astype(str).str.upper().value_counts()
    )

high_threats = int(severity_counts.get("HIGH", 0))
medium_threats = int(severity_counts.get("MEDIUM", 0))
low_threats = int(severity_counts.get("LOW", 0))

risk_score = 0
if total_threats:
    risk_score = round(
        sum(calculate_risk(row) for _, row in threats.iterrows())
        / total_threats
    )

ip_addresses = sorted(set(
    get_ip_addresses(logs) + get_ip_addresses(threats)
))


# --------------------------------------------------
# MAIN HEADER
# --------------------------------------------------

st.markdown("""
<div class="soc-banner">
    <div class="soc-small">◈ CYBER DEFENSE NETWORK // SECURE CONNECTION</div>
    <div class="soc-title">🛡️ CYBER SENTINEL SOC</div>
    <div class="soc-subtitle">
        AI Threat Intelligence | Live Security Monitoring |
        Incident Investigation | Autonomous Response
    </div>
    <br>
    <span class="status-pill">● SECURITY MONITORING ACTIVE</span>
</div>
""", unsafe_allow_html=True)


# --------------------------------------------------
# DASHBOARD OVERVIEW
# --------------------------------------------------

if page == "Dashboard Overview":

    st.header("📊 Security Command Center")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Events", total_events)
    col2.metric("Detected Threats", total_threats)
    col3.metric("High Threats", high_threats)
    col4.metric("Medium Threats", medium_threats)
    col5.metric("Risk Score", f"{risk_score}/100")

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("🎯 Threat Severity Distribution")

        if not severity_counts.empty:
            chart_df = severity_counts.reset_index()
            chart_df.columns = ["Severity", "Count"]

            fig = px.pie(
                chart_df,
                names="Severity",
                values="Count",
                hole=0.55,
                color="Severity",
                color_discrete_map={
                    "HIGH": "#ff4560",
                    "MEDIUM": "#ffb020",
                    "LOW": "#28d7a1"
                }
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="white"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No severity data available.")

    with right:
        st.subheader("📈 Threat Level Overview")

        chart_df = pd.DataFrame({
            "Severity": ["High", "Medium", "Low"],
            "Count": [high_threats, medium_threats, low_threats]
        })

        fig = px.bar(
            chart_df,
            x="Severity",
            y="Count",
            color="Severity",
            color_discrete_map={
                "High": "#ff4560",
                "Medium": "#ffb020",
                "Low": "#28d7a1"
            }
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()
    st.subheader("🚨 Recent Security Threats")
    show_data(threats.tail(5), "No recent threats detected.")

    st.subheader("🧠 Overall Security Risk")
    st.progress(risk_score / 100)
    st.write(f"Current calculated risk score: **{risk_score}/100**")


# --------------------------------------------------
# LIVE ACTIVITY FEED
# --------------------------------------------------

elif page == "Live Activity Feed":

    st.header("📡 Live Security Activity Feed")
    st.caption("Latest events from the log collector. Refresh to fetch updated logs.")

    if st.button("Refresh Activity"):
        st.cache_data.clear()
        st.rerun()

    if not logs.empty:
        st.dataframe(
            logs.tail(50),
            use_container_width=True,
            hide_index=True
        )
        st.caption(f"Displaying up to 50 of {total_events} collected events.")
    else:
        st.info("No activity events available.")


# --------------------------------------------------
# ATTACK ANALYTICS
# --------------------------------------------------

elif page == "Attack Analytics":

    st.header("📈 Advanced Attack Analytics")

    if not threats.empty:

        if "severity" in threats.columns:
            st.subheader("Threats by Severity")

            severity_df = (
                threats["severity"].astype(str).str.upper()
                .value_counts().reset_index()
            )
            severity_df.columns = ["Severity", "Count"]

            fig = px.bar(
                severity_df,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map={
                    "HIGH": "#ff4560",
                    "MEDIUM": "#ffb020",
                    "LOW": "#28d7a1"
                }
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="white"
            )
            st.plotly_chart(fig, use_container_width=True)

        text_columns = [
            col for col in threats.columns
            if threats[col].dtype == "object"
        ]

        possible_type = next(
            (col for col in text_columns
             if any(word in col.lower()
                    for word in ["attack", "type", "threat", "event"])),
            None
        )

        if possible_type:
            st.subheader("Attack Categories")
            category_df = (
                threats[possible_type].astype(str)
                .value_counts().head(10).reset_index()
            )
            category_df.columns = ["Attack Type", "Count"]

            fig = px.bar(
                category_df,
                x="Count",
                y="Attack Type",
                orientation="h",
                color="Count",
                color_continuous_scale="Plasma"
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="white"
            )
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Threat Data")
        st.dataframe(threats, use_container_width=True, hide_index=True)

    else:
        st.info("Attack analytics will appear when threats are detected.")


# --------------------------------------------------
# SECURITY EVENT LOGS
# --------------------------------------------------

elif page == "Security Event Logs":

    st.header("📁 Security Event Logs")

    if not logs.empty:

        search = st.text_input("🔎 Search logs")

        filtered_logs = logs.copy()

        if search:
            mask = filtered_logs.astype(str).apply(
                lambda column: column.str.contains(
                    search, case=False, na=False
                )
            ).any(axis=1)
            filtered_logs = filtered_logs[mask]

        st.write(f"Matching events: {len(filtered_logs)}")

        st.dataframe(
            filtered_logs,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇️ Download Event Logs CSV",
            data=filtered_logs.to_csv(index=False).encode("utf-8"),
            file_name="cyber_sentinel_logs.csv",
            mime="text/csv"
        )

    else:
        st.info("No security logs available.")


# --------------------------------------------------
# THREAT INVESTIGATION
# --------------------------------------------------

elif page == "Threat Investigation":

    st.header("🔍 Threat Investigation")

    if not threats.empty:

        st.dataframe(threats, use_container_width=True, hide_index=True)

        if "severity" in threats.columns:

            for level in ["HIGH", "MEDIUM", "LOW"]:

                filtered = threats[
                    threats["severity"].astype(str).str.upper() == level
                ]

                with st.expander(
                    f"{level} Severity Threats ({len(filtered)})"
                ):
                    st.dataframe(
                        filtered,
                        use_container_width=True,
                        hide_index=True
                    )

    else:
        st.success("No threats detected.")


# --------------------------------------------------
# IP INTELLIGENCE
# --------------------------------------------------

elif page == "IP Intelligence":

    st.header("🌐 IP Intelligence Center")
    st.caption(
        "Basic local IP classification. This is not a live external "
        "IP reputation or threat-intelligence lookup."
    )

    if ip_addresses:

        ip_rows = []

        for address in ip_addresses:
            category, assessment = local_ip_assessment(address)

            ip_rows.append({
                "IP Address": address,
                "Classification": category,
                "Assessment": assessment
            })

        ip_df = pd.DataFrame(ip_rows)

        st.metric("Unique IP Addresses", len(ip_df))
        st.dataframe(ip_df, use_container_width=True, hide_index=True)

        selected_ip = st.selectbox("Inspect an IP address", ip_addresses)

        category, assessment = local_ip_assessment(selected_ip)

        st.subheader("IP Assessment")
        st.write(f"**Address:** {selected_ip}")
        st.write(f"**Classification:** {category}")
        st.info(assessment)

    else:
        st.info("No IP addresses found in the collected data.")


# --------------------------------------------------
# AI INCIDENT ANALYSIS
# --------------------------------------------------

elif page == "AI Incident Analysis":

    st.header("🤖 AI Incident Analysis")
    st.caption("Analysis generated by your existing AI analysis module.")

    if isinstance(analysis, pd.DataFrame):
        show_data(analysis, "No AI analysis available.")

    elif isinstance(analysis, (list, tuple)):

        if analysis:
            for index, item in enumerate(analysis):
                with st.expander(f"Incident Analysis {index + 1}"):
                    st.write(item)
        else:
            st.info("No AI analysis available.")

    elif isinstance(analysis, dict):

        for key, value in analysis.items():
            with st.expander(str(key)):
                st.write(value)

    elif analysis is not None:
        st.write(analysis)

    else:
        st.info("No AI analysis available.")

    if not threats.empty:
        st.divider()
        st.subheader("🧠 AI-Assisted Risk Assessment")

        risk_df = threats.copy()
        risk_df["Calculated Risk Score"] = risk_df.apply(
            calculate_risk, axis=1
        )

        st.dataframe(
            risk_df,
            use_container_width=True,
            hide_index=True
        )

        st.caption(
            "Risk scores are calculated from severity labels. "
            "They are not a trained predictive AI model."
        )


# --------------------------------------------------
# INCIDENT MANAGEMENT
# --------------------------------------------------

elif page == "Incident Management":

    st.header("🚨 Incident Management")
    st.caption("Track and update the status of detected incidents.")

    if not threats.empty:

        if "incident_statuses" not in st.session_state:
            st.session_state.incident_statuses = {}

        for index, row in threats.reset_index(drop=True).iterrows():

            severity = str(row.get("severity", "UNKNOWN")).upper()
            incident_name = str(
                row.get("threat", row.get("event", f"Incident {index + 1}"))
            )

            with st.container(border=True):

                st.subheader(f"Incident #{index + 1}: {incident_name}")

                col1, col2 = st.columns(2)

                with col1:
                    st.write(f"**Severity:** {severity}")
                    st.write(f"**Risk Score:** {calculate_risk(row)}/100")

                with col2:
                    current_status = st.session_state.incident_statuses.get(
                        index, "Open"
                    )

                    new_status = st.selectbox(
                        "Incident Status",
                        ["Open", "Investigating", "Resolved"],
                        index=["Open", "Investigating", "Resolved"].index(
                            current_status
                        ),
                        key=f"status_{index}"
                    )

                    st.session_state.incident_statuses[index] = new_status

                st.dataframe(
                    pd.DataFrame([row]),
                    use_container_width=True,
                    hide_index=True
                )

        status_values = list(st.session_state.incident_statuses.values())

        st.divider()
        st.subheader("Incident Status Summary")

        st.write(f"Open: {status_values.count('Open')}")
        st.write(f"Investigating: {status_values.count('Investigating')}")
        st.write(f"Resolved: {status_values.count('Resolved')}")

    else:
        st.success("No incidents to manage.")


# --------------------------------------------------
# INCIDENT RESPONSE
# --------------------------------------------------

elif page == "Incident Response":

    st.header("⚡ Incident Response")
    st.caption("Recommendations from your existing response module.")

    if isinstance(responses, pd.DataFrame):
        show_data(responses, "No response recommendations available.")

    elif isinstance(responses, (list, tuple)):

        if responses:
            for index, response in enumerate(responses):
                with st.expander(f"Response Recommendation {index + 1}"):
                    st.write(response)
        else:
            st.info("No response recommendations available.")

    elif isinstance(responses, dict):

        for key, value in responses.items():
            with st.expander(str(key)):
                st.write(value)

    elif responses is not None:
        st.write(responses)

    else:
        st.info("No response recommendations available.")

    st.warning(
        "This prototype displays response recommendations. "
        "It does not automatically block IPs or modify accounts."
    )


# --------------------------------------------------
# SECURITY REPORTS
# --------------------------------------------------

elif page == "Security Reports":

    st.header("📄 Security Reports")
    st.caption("Export a summary of the current collected security data.")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Events", total_events)
    col2.metric("Threats", total_threats)
    col3.metric("High", high_threats)
    col4.metric("Risk Score", f"{risk_score}/100")

    st.divider()

    st.subheader("Download Reports")

    report_df = threats.copy()

    st.download_button(
        "⬇️ Download Threat Report (CSV)",
        data=report_df.to_csv(index=False).encode("utf-8"),
        file_name="cyber_sentinel_threat_report.csv",
        mime="text/csv"
    )

    st.download_button(
        "⬇️ Download Security Logs (CSV)",
        data=logs.to_csv(index=False).encode("utf-8"),
        file_name="cyber_sentinel_security_logs.csv",
        mime="text/csv"
    )

    pdf_file = make_pdf_report(
        total_events,
        total_threats,
        high_threats,
        medium_threats,
        low_threats,
        threats
    )

    if pdf_file:
        st.download_button(
            "⬇️ Download Security Report (PDF)",
            data=pdf_file,
            file_name="cyber_sentinel_report.pdf",
            mime="application/pdf"
        )
    else:
        st.warning(
            "PDF generation requires ReportLab. "
            "Install it using: pip install reportlab"
        )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.markdown("""
<div style="text-align:center; color:#8296c5; padding:12px;">
    🛡️ <b>CYBER SENTINEL SOC</b><br>
    AI-Powered Autonomous Security Operations Center<br>
    <small>Security Monitoring • Threat Intelligence • Incident Management</small>
</div>
""", unsafe_allow_html=True)
