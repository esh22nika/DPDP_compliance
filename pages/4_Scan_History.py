import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px

# Set page title and layout
st.set_page_config(page_title="Scan History & Insights", layout="wide")
st.title(" Security Scan Insights Dashboard")

# Custom CSS for rounded blue graph panels
st.markdown("""
    <style>
        .chart-container {
            background-color: #E3F2FD; /* Light Blue */
            padding: 20px;
            border-radius: 15px;
            box-shadow: 2px 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 15px;
        }
    </style>
""", unsafe_allow_html=True)

# Connect to the database
DB_PATH = "security_scans.db"

def load_data():
    """Load scan data from the database"""
    conn = sqlite3.connect(DB_PATH)
    port_scans = pd.read_sql_query("SELECT * FROM port_scans", conn)
    vulnerabilities = pd.read_sql_query("SELECT * FROM vulnerability_scans", conn)
    domain_metadata = pd.read_sql_query("SELECT * FROM domain_metadata", conn)
    domain_metadata['timestamp'] = pd.to_datetime(domain_metadata['timestamp'], errors='coerce')

    conn.close()
    return port_scans, vulnerabilities, domain_metadata

# Load data
port_scans, vulnerabilities, domain_metadata = load_data()

# Convert timestamps to datetime
port_scans['timestamp'] = pd.to_datetime(port_scans['timestamp'])
vulnerabilities['timestamp'] = pd.to_datetime(vulnerabilities['timestamp'])
domain_metadata['timestamp'] = pd.to_datetime(domain_metadata['timestamp'])

# 📌 Sidebar Filters
st.sidebar.header(" Filters")
date_range = st.sidebar.date_input("Select Date Range", [])
selected_domain = st.sidebar.selectbox("Select Domain", ["All"] + list(port_scans['domain'].unique()))

# Apply filters
if date_range:
    start_date, end_date = date_range
    port_scans = port_scans[(port_scans['timestamp'] >= pd.to_datetime(start_date)) & (port_scans['timestamp'] <= pd.to_datetime(end_date))]
    vulnerabilities = vulnerabilities[(vulnerabilities['timestamp'] >= pd.to_datetime(start_date)) & (vulnerabilities['timestamp'] <= pd.to_datetime(end_date))]
    domain_metadata = domain_metadata[(domain_metadata['timestamp'] >= pd.to_datetime(start_date)) & (domain_metadata['timestamp'] <= pd.to_datetime(end_date))]

if selected_domain != "All":
    port_scans = port_scans[port_scans['domain'] == selected_domain]
    vulnerabilities = vulnerabilities[vulnerabilities['domain'] == selected_domain]
    domain_metadata = domain_metadata[domain_metadata['domain'] == selected_domain]

# **Graphs**
security_scores = domain_metadata[['domain', 'timestamp', 'ssl_expiry']].groupby(['timestamp']).count().reset_index()
fig1 = px.line(security_scores, x='timestamp', y='ssl_expiry', markers=True, title="Security Score Trends")

vuln_counts = vulnerabilities[['sql_injection_risk', 'xss_risk', 'api_exposure', 'sensitive_data_risk']].apply(pd.Series.value_counts).fillna(0)
vuln_counts = vuln_counts.sum(axis=1).reset_index()
vuln_counts.columns = ['Vulnerability', 'Count']
fig2 = px.bar(vuln_counts, x='Vulnerability', y='Count', color='Vulnerability', title="Top Security Risks")

all_ports = []
for entry in port_scans['open_ports']:
    all_ports.extend(eval(entry))  
port_counts = pd.Series(all_ports).value_counts().reset_index()
port_counts.columns = ['Port', 'Count']
fig3 = px.pie(port_counts, values='Count', names='Port', title="Exposed Ports")

vuln_data = vulnerabilities.melt(id_vars=['domain'], value_vars=['sql_injection_risk', 'xss_risk', 'api_exposure', 'sensitive_data_risk'])
vuln_data = vuln_data[vuln_data['value'] == 'Yes']
fig4 = px.bar(vuln_data, x='domain', color='variable', title="Vulnerabilities per Domain", barmode="stack")

status_counts = domain_metadata['geolocation_risk'].value_counts().reset_index()
status_counts.columns = ['Status', 'Count']
fig5 = px.pie(status_counts, values='Count', names='Status', hole=0.4, title="Scan Results Status")

#  **Power BI-Style Layout: 3 Charts on Top, 2 Below**
st.markdown("###  Security Insights")

col1, col2, col3 = st.columns(3)
with col1:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown("####  Security Score Over Time")
    st.plotly_chart(fig1, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown("#### 🛠 Most Common Vulnerabilities")
    st.plotly_chart(fig2, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col3:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown("####  Open Ports Distribution")
    st.plotly_chart(fig3, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

col4, col5 = st.columns(2)
with col4:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown("####  Vulnerability Distribution by Domain")
    st.plotly_chart(fig4, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col5:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown("####  Scan Status Overview")
    st.plotly_chart(fig5, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

#  **Download Scan Data**
st.markdown("###  Download Scan Data")
csv_data = port_scans.to_csv(index=False)
st.download_button("⬇Download Scan History (CSV)", data=csv_data, file_name="scan_history.csv", mime="text/csv")

# 🔙 **Navigation**
st.button("🔙 Back to Dashboard", on_click=lambda: st.switch_page("pages/1_Dashboard.py"))
