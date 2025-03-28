import streamlit as st
import time
import sqlite3
import pandas as pd
import plotly.express as px
from pages.Privacy_Check import find_privacy_policy_url as ifFound
from pages.Privacy_Check import main as run_privacy_check
from pages.Generate_Policy import generate_policy_page as genPolicy

st.title("Dashboard")

if not st.session_state.user:
    st.info("Please login/signup to access all features")
else:
    def log_scan(username, website_url, status):
        """Logs each scan into the database."""
        conn = sqlite3.connect("security_scans.db")
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scans (username, scan_date, website_url, status)
            VALUES (?, datetime('now'), ?, ?)
        """, (username, website_url, status))
        
        conn.commit()
        conn.close()
    
    # URL Input
    url = st.text_input("Enter Website URL")
    if url:
        with st.spinner("Scanning for Privacy Policy..."):
            policy_url, response = ifFound(url)
            if not policy_url or not response:
                st.error("Couldn't find a privacy policy on your website.")
                log_scan(st.session_state.user["name"], url, "Failed")  # ✅ Log scan only once
                
                with st.expander("Need a privacy policy template?"):
                    st.markdown("""
                    We can help you create a basic privacy policy template.
                    
                    **Note:** This template should be reviewed by a legal professional before use.
                    """)
                if st.button("Generate Policy"):
                    st.session_state['policy_url'] = url  # Pass URL through session state
                    st.switch_page("pages/Generate_Policy.py")
                
                if st.button("Run Security Scan"):
                    st.session_state['policy_url'] = url
                    st.switch_page("pages/3_Security_Scan.py")
            else:
                run_privacy_check(url)
                log_scan(st.session_state.user["name"], url, "Completed")  # ✅ Log scan once
                if st.button("Run Security Scan"):
                    st.session_state['policy_url'] = url
                    st.switch_page("pages/3_Security_Scan.py")
        
    else:
        # ✅ Security Scan Stats (Graphical Representation)
        st.subheader("Security Scan Statistics")

        def fetch_scan_stats():
            """Fetch real scan stats from SQLite database."""
            conn = sqlite3.connect("security_scans.db")
            cursor = conn.cursor()

            cursor.execute("SELECT scan_date, website_url, status FROM scans WHERE username = ? ORDER BY scan_date DESC LIMIT 4", 
                        (st.session_state.user["name"],))
            
            data = cursor.fetchall()
            conn.close()

            df = pd.DataFrame(data, columns=["scan_date", "website_url", "status"])
            df["scan_date"] = pd.to_datetime(df["scan_date"]).dt.date  # Keep only date, remove time
            return df

        # Fetch data
        scan_df = fetch_scan_stats()

        if not scan_df.empty:
            col1, col2 = st.columns(2)
            with col1:
                # 🥧 Pie Chart: Scan Status Distribution (Last 4 scans)
                scan_counts = scan_df["status"].value_counts().reset_index()
                scan_counts.columns = ["Status", "Count"]
                pie_chart = px.pie(scan_counts, names="Status", values="Count", 
                                title="Scan Status Distribution (Last 4 Scans)", 
                                color="Status", color_discrete_map={"Completed": "#28a745", "Failed": "#dc3545"},
                                labels={"Status": "Scan Status", "Count": "Count"}, 
                                template="plotly_dark", 
                                hole=0.4)  # Add a hole for a donut-style pie chart
                st.plotly_chart(pie_chart, use_container_width=True)
            
            with col2:
                # Line Chart: Daily Scan Activity (Last 4 scans) with separate colors
                scan_df['scan_instance'] = range(1, len(scan_df) + 1)  # Ensure unique identifiers for each scan
                line_chart = px.line(scan_df, x="scan_instance", y="status", 
                                    title="Daily Scan Activity (Last 4 Scans)", 
                                    labels={"scan_instance": "Scan Instance", "status": "Scan Status"}, 
                                    markers=True, 
                                    color="status", 
                                    color_discrete_map={"Completed": "#28a745", "Failed": "#dc3545"}, 
                                    line_shape="spline",  # Smoothing the lines for a better visual flow
                                    template="plotly_dark", 
                                    height=400)  # Increase chart height for better visual clarity
                st.plotly_chart(line_chart, use_container_width=True)
        else:
            st.info("No scan data available. Perform a scan to see stats!")

