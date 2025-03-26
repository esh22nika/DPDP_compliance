import streamlit as st

# Initialize session state for user login
if "user" not in st.session_state:
    st.session_state["user"] = None  # Default value when not logged in

# Check if the user is logged in
if not st.session_state["user"]:
    st.info("Please login/signup to access all features")
else:
    st.title("About Us – ComplyEase")

    st.write(
        """
        ### What We Do  
        At **ComplyEase**, we help businesses comply with India's **Digital Personal Data Protection (DPDP) Act** by ensuring secure and legally compliant handling of personal data.  

        ✅ **Data Protection Compliance** – Implement DPDP-compliant data policies.  
        ✅ **User Consent Management** – Securely collect, store, and manage user consent.  
        ✅ **Privacy & Security Audits** – Conduct compliance audits and risk assessments.  
        ✅ **Automated Compliance Tools** – Provide AI-driven solutions for data governance.  
        ✅ **Education & Awareness** – Offer resources and training on data protection best practices.  

        ### Our Mission  
        We strive to make **data privacy simple, secure, and legally compliant** for businesses and individuals, ensuring they meet the latest regulatory standards without compromising efficiency.
        """
    )

