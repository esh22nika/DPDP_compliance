import streamlit as st
import time
import google.generativeai as genai

url = st.session_state.get('policy_url')


# genai.configure(api_key=st.secrets["GEMINI_API_KEY"])
genai.configure(api_key='AIzaSyDZjor43yqVq4bWRThkg-EraIh6vmlCw6s')
def generate_ai_policy(inputs):
    """Generate privacy policy using Gemini"""
    model = genai.GenerativeModel('gemini-1.5-flash')
    prompt = f"""
    Create a DPDP Act 2023 compliant privacy policy for an Indian business using this information:
    
    Business Name: {inputs['business_name']}
    Contact Email: {inputs['contact_email']}
    Physical Address: {inputs['physical_address']}
    
    Data Collected: {inputs['data_collected']}
    Consent Method: {inputs['consent_method']}
    Security Measures: {inputs['security_measures']}
    
    
    S
    
    Format in clear English with these sections:
    1. Introduction
    2. Information We Collect
    3. How We Use Data
    4. Data Sharing
    5. Your Rights (DPDP)
    6. Security Measures
    7. Contact Information
    
    Include required DPDP elements:
    - Grievance Officer details
    - Data localization status
    - Breach notification
    - Consent withdrawal process
    [FORMAT]
    - Plain English
    - DPDP 2023 compliant
    - Markdown sections
    - Include grievance officer details
    - 500 words maximum
    - make changes if new regulatory changes made to DPDP
    """

    response = model.generate_content(prompt)
    return response.text

def generate_simple_dpdp_policy():
    with st.expander(" Create Your Free Privacy Policy (DPDP Act Compliant)", expanded=True):
        
        
        # Business Basics
        st.subheader(" About Your Business")
        business_name = st.text_input("Your Business Name*")
        website_url = st.text_input("Your Website Address*", value=url)
        contact_email = st.text_input("Contact Email for Privacy Questions*")
        physical_address = st.text_input("Your Business Address*")
        
        st.markdown("---")
        
        # Data Collection
        st.subheader(" What Information Do You Collect?")
        st.markdown("**Tick all that apply:**")
        
        col1, col2 = st.columns(2)
        with col1:
            collects_name = st.checkbox("Customer Names", True)
            collects_email = st.checkbox("Email Addresses", True)
            collects_phone = st.checkbox("Phone Numbers")
            collects_address = st.checkbox("Home/Office Addresses")
        
        with col2:
            collects_payment = st.checkbox("Payment Details")
            collects_id = st.checkbox("Government IDs (Aadhaar, PAN etc)")
            collects_location = st.checkbox("Location Data")
            collects_other = st.text_input("Other (please specify)")
        
        st.markdown("---")
        
        # DPDP-Specific Enhancements
        st.subheader("Data Retention Rules")
        retention_period = st.number_input(
            "Maximum retention period (months)*",
            min_value=1, value=24
        )

        st.subheader("Third-Party Data Sharing")
        third_parties = st.multiselect(
            "Select partners:",
            ["Payment Processors", "Cloud Providers", "Marketing Agencies"]
        )
        data_processing_agreements = st.checkbox("We have valid Data Processing Agreements", True)

        st.subheader(" Children's Data (Under 18)")
        child_data = st.checkbox("Collect minor's data?")
        age_verification = None
        if child_data:
            age_verification = st.selectbox(
                "Age verification method:",
                ["Parental Consent via OTP", "Age Gate (13+)"]
            )

        st.subheader("Data Storage Location")
        data_localization = st.radio(
            "Primary data storage:",
            ["Only India", "India + International", "Only International"]
        )

        st.subheader("Grievance Redressal")
        dpo_name = st.text_input("Grievance Officer Name*")
        dpo_email = st.text_input("Grievance Officer Email*")

        st.subheader("Compliance Measures")
        compliance_audits = st.checkbox("Annual DPDP audits", True)
        audit_trails = st.checkbox("Maintain audit trails", True)
        incident_plan = st.checkbox("Data breach response plan", True)

        st.subheader("Data Usage Purposes")
        data_purposes = st.multiselect(
            "Select purposes:",
            ["Service Delivery", "Legal Compliance", "Fraud Prevention"],
            default=["Service Delivery"]
        )

        st.subheader("Consent Management")
        consent_method = st.radio(
            "Permission method:",
            ["Checkbox Agreement", "Written Form", "Implied Consent"]
        )
        has_withdraw = st.checkbox("Allow consent withdrawal", True)
        
        st.subheader(" Customer Rights")
        right_access = st.checkbox("Access Data", True)
        right_correct = st.checkbox("Correct Data", True)
        right_delete = st.checkbox("Delete Data", True)
        right_complain = st.checkbox("File Complaints", True)

        st.subheader(" Security Measures")
        secure_passwords = st.checkbox("Password Protection", True)
        secure_encrypt = st.checkbox("Encryption", True)
        secure_staff = st.checkbox("Staff Training")
        secure_backup = st.checkbox("Regular Backups")

        if st.button("Generate My Privacy Policy", type="primary"):
            if not all([business_name, website_url, contact_email]):
                st.warning("Please fill all required fields")
                return
            
            with st.spinner("Creating your policy..."):
                time.sleep(1)
                # Update this in your Generate button click handler
        inputs ={
                    # Business Info
                    'business_name': business_name,
                    'website_url': website_url,
                    'contact_email': contact_email,
                    'physical_address': physical_address,
                    
                    # Data Collection
                    'data_collected': [
                        *(['Names'] if collects_name else []),
                        *(['Emails'] if collects_email else []),
                        *(['Phone Numbers'] if collects_phone else []),
                        *(['Addresses'] if collects_address else []),
                        *(['Payment Details'] if collects_payment else []),
                        *(['Government IDs'] if collects_id else []),
                        *(['Location Data'] if collects_location else []),
                        *([collects_other] if collects_other else [])
                    ],
                    
                    
                    'retention_period': retention_period,
                    'third_parties': third_parties,
                    'data_processing_agreements': data_processing_agreements,
                    'child_data': {
                        'collects': child_data,
                        'verification_method': age_verification if child_data else None
                    },
                    'data_localization': data_localization,
                    'dpo_details': {
                        'name': dpo_name,
                        'email': dpo_email
                    },
                    'compliance_measures': [
                        *(['Annual Audits'] if compliance_audits else []),
                        *(['Audit Trails'] if audit_trails else []),
                        *(['Incident Plan'] if incident_plan else [])
                    ],
                    'data_purposes': data_purposes,
                    
                    # Consent & Rights
                    'consent_method': consent_method,
                    'consent_withdrawal': has_withdraw,
                    'user_rights': [
                        *(['Access Data'] if right_access else []),
                        *(['Correct Data'] if right_correct else []),
                        *(['Delete Data'] if right_delete else []),
                        *(['File Complaints'] if right_complain else [])
                    ],
                    
                    # Security Measures
                    'security_measures': [
                        *(['Password Protection'] if secure_passwords else []),
                        *(['Encryption'] if secure_encrypt else []),
                        *(['Staff Training'] if secure_staff else []),
                        *(['Regular Backups'] if secure_backup else [])
                    ]
                    
                    
                }
                # Build policy content
        policy = generate_ai_policy(inputs)
        st.success("Your Privacy Policy")
        st.markdown(policy)
                
        st.download_button(
            "Download Policy",
            policy,
            file_name=f"{business_name}_Privacy_Policy.txt"
        )

def generate_policy_page():
    st.set_page_config(page_title="Privacy Policy Generator")
    st.title("Privacy Policy Generator")
    
    if not st.session_state.get('user'):
        st.warning("Please login to access the policy generator")
        return
    
    generate_simple_dpdp_policy()
    if st.button("Run Security Scan"):
        st.switch_page("pages/3_Security_Scan.py")
    if st.button("Go back to dashboard"):
        st.switch_page("pages/1_Dashboard.py")
        

if __name__ == "__main__":
    generate_policy_page()