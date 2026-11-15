import streamlit as st
import plotly.express as px

from log_collector import collect_logs
from threat_detection import detect_threats
from incident_response import respond_to_incidents
from ai_analysis import analyze_incidents

st.set_page_config(
    page_title="AI SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Powered Autonomous SOC")
st.subheader("Security Operations & Intelligent Incident Response")

# Collect security logs
logs = collect_logs()

# Detect threats
threats = detect_threats(logs)

# Analyze incidents
analysis = analyze_incidents(threats)

# Generate response recommendations
responses = respond_to_incidents(threats)

# Dashboard metrics
col1, col2, col3 = st.columns(3)

col1.metric("Total Security Events", len(logs))
col2.metric("Detected Threats", len(threats))
col3.metric("High Severity Threats", len(threats[threats["severity"] == "HIGH"]))

st.divider()

# Security logs
st.header("Security Logs")
st.dataframe(logs, use_container_width=True)

# Threat detection
st.header("Threat Detection")
if not threats.empty:
    st.dataframe(threats, use_container_width=True)
else:
    st.success("No threats detected.")

# AI incident analysis
st.header("AI Incident Analysis")
if not analysis.empty:
    st.dataframe(
        analysis[["username", "severity", "ai_analysis"]],
        use_container_width=True
    )

# Incident response
st.header("Intelligent Incident Response")
if not responses.empty:
    st.dataframe(
        responses[["username", "ip_address", "response_action"]],
        use_container_width=True
    )

# Threat chart
st.header("Threat Severity Overview")

if not threats.empty:
    chart = px.pie(
        threats,
        names="severity",
        title="Detected Threats by Severity"
    )
    st.plotly_chart(chart, use_container_width=True)

st.success("SOC Dashboard Loaded Successfully!")