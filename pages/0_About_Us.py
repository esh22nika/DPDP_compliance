import streamlit as st
if not st.session_state.user:
    st.info("Please login/signup to access all features")
else:
    st.title("About Us")
    st.write("Your about us content here")

