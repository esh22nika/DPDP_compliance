import streamlit as st

st.title("Settings")

if not st.session_state.user:
    st.info("Please login/signup to access all features")

else:
    st.write(f"Account Settings for {st.session_state.user['username']}")
    # Add settings components

  
