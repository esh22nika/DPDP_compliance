import streamlit as st
import time
from pages.Privacy_Check import main as run_privacy_check

st.title("Dashboard")
if not st.session_state.user:
    st.info("Please login/signup to access all features")
else:
    # URL Input
    url = st.text_input("Enter Website URL")
    if url:
        with st.spinner("Scanning for Privacy Policy..."):
            time.sleep(2)  # Simulate scanning
            run_privacy_check(url)
            # Simulate policy check
            #if "example.com" in url:
             #   st.success("Privacy Policy Found!")
            #st.switch_page("pages/Privacy_Check.py")
'''
                st.metric("Compliance Score", "82%")
                
                if st.button("Fix Issues"):
                    st.switch_page("pages/7_Privacy_Check.py")
                
                if st.button("Run Security Scan"):
                    st.switch_page("pages/3_Security_Scan.py")
            else:
                st.error("No Privacy Policy Found")
                if st.button("Generate Policy"):
                    st.switch_page("pages/2_Generate_Policy.py")
'''
