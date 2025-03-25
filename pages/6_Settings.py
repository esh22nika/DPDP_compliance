import streamlit as st

st.title("Settings")

if st.session_state.user:
    st.write(f"Account Settings for {st.session_state.user['username']}")
    # Add settings components
else:
    st.write("About Us")
    st.write("DPDP Act Information")