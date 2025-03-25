import streamlit as st
from auth import login, signup, create_users_table

# Initialize database
create_users_table()

# Session state initialization
if 'user' not in st.session_state:
    st.session_state.user = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Dashboard"

# Sidebar handling
with st.sidebar:
    if st.session_state.user:
        st.write(f"Welcome {st.session_state.user['name']}!")
        st.page_link("main.py", label="Dashboard")
        st.page_link("pages/3_Security_Scan.py", label="Security Scan")
        st.page_link("pages/4_Scan_History.py", label="Scan History")
        st.page_link("pages/5_Roadmap.py", label="Roadmap")
        st.page_link("pages/6_Settings.py", label="Settings")
        
        if st.button("Logout"):
            st.session_state.user = None
            st.rerun()
    #else:
    
    #   st.page_link("main.py", label="Home")
    # st.page_link("pages/6_Settings.py", label="About")

# Main page routing
if not st.session_state.user:
    st.title("DPDP Compliance Checker")
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        login()
    with tab2:
        signup()
else:
    if st.session_state.current_page == "Dashboard":
        st.switch_page("pages/1_Dashboard.py")