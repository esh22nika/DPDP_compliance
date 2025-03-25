import streamlit as st
import time

st.title("Generate Privacy Policy")

# Policy form
with st.form("policy_details"):
    company_name = st.text_input("Company Name")
    data_types = st.multiselect("Data Collected", ["Personal", "Demographic", "Behavioral"])
    # Add more fields as needed
    
    if st.form_submit_button("Generate"):
        with st.spinner("Generating Policy..."):
            # Generate policy logic here
            time.sleep(2)
            st.success("Policy Generated!")
            
            # Display generated policy
            st.text_area("Generated Policy", "Your privacy policy text...")
            
            # Download button
            st.download_button(
                label="Download PDF",
                data="Policy content",
                file_name="privacy_policy.pdf"
            )
            
            if st.button("Run Security Scan"):
                st.switch_page("pages/3_Security_Scan.py")