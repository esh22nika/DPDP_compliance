import streamlit as st

st.title("Compliance Roadmap")

st.write("""
### Step-by-Step Guide
1. Fix XSS vulnerabilities
2. Implement data encryption
3. Update privacy policy
4. Regular security audits
""")

if st.button("Back to Dashboard"):
    st.switch_page("main.py")