import streamlit as st
import time
from pages.Privacy_Check import find_privacy_policy_url as ifFound
from pages.Privacy_Check import main as run_privacy_check
from pages.Generate_Policy import generate_policy_page as genPolicy
st.title("Dashboard")
if not st.session_state.user:
    st.info("Please login/signup to access all features")
else:
    # URL Input
    url = st.text_input("Enter Website URL")
    if url:
        with st.spinner("Scanning for Privacy Policy..."):
            
            
            policy_url, response = ifFound(url)
            if not policy_url or not response:
                st.error("Couldn't find a privacy policy on your website.")
                
                with st.expander("Need a privacy policy template?"):
                    st.markdown("""
                    We can help you create a basic privacy policy template.
                    
                    **Note:** This template should be reviewed by a legal professional before use.
                    """)
                if st.button("Generate Policy"):
                    st.session_state['policy_url'] = url  # Pass URL through session state
                    st.switch_page("pages/Generate_Policy.py")
                        
               # if st.button("Fix Issues"):
               #      st.switch_page("pages/7_Privacy_Check.py")
                
                if st.button("Run Security Scan"):
                    st.switch_page("pages/3_Security_Scan.py")
            else:
                run_privacy_check(url)
                if st.button("Run Security Scan"):
                    st.switch_page("pages/3_Security_Scan.py")
                      

