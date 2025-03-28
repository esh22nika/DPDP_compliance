import streamlit as st
import requests
from PyPDF2 import PdfReader
from io import BytesIO
import os
import difflib
from datetime import datetime
from plyer import notification

# PDF URL from MeitY
PDF_URL = "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf"
TEXT_FILE = "dpdp_act_2023.txt"

def fetch_dpdp_data():
    """Fetches the DPDP Act text from the MeitY PDF."""
    try:
        # Download PDF
        response = requests.get(PDF_URL, timeout=10)
        response.raise_for_status()
        
        # Extract text
        pdf_file = BytesIO(response.content)
        reader = PdfReader(pdf_file)
        text = ""
        
        for page in reader.pages:
            text += page.extract_text() + "\n"
        
        # Clean up text
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines)
    
    except Exception as e:
        st.error(f"Error fetching PDF: {str(e)}")
        return None

def save_text_to_file(text, filename):
    """Saves text data to a file."""
    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write(text)
        return True
    except IOError as e:
        st.error(f"Error saving file: {str(e)}")
        return False

def load_previous_text(filename):
    """Loads previously stored text data."""
    try:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as file:
                return file.read()
        return None
    except IOError as e:
        st.error(f"Error reading file: {str(e)}")
        return None

def send_notification(title, message):
    """Sends a desktop notification when updates are found."""
    notification.notify(
        title=title,
        message=message,
        app_name="DPDP Compliance Checker",
        timeout=10
    )

def check_for_updates():
    """Checks if the DPDP Act text has changed."""
    new_text = fetch_dpdp_data()
    last_checked = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if new_text:
        old_text = load_previous_text(TEXT_FILE)
        
        if old_text is None:
            if save_text_to_file(new_text, TEXT_FILE):
                return "ℹ First-time check. DPDP Act content saved.", last_checked, []
            else:
                return "⚠ Error saving initial data", last_checked, []

        if new_text != old_text:
            diff = list(difflib.ndiff(old_text.splitlines(), new_text.splitlines()))
            changes = [line for line in diff if line.startswith("+ ") or line.startswith("- ")]
            
            if save_text_to_file(new_text, TEXT_FILE):
                send_notification(
                    "DPDP Update Alert!", 
                    "New changes detected in the official DPDP Act PDF!"
                )
                return "🔔 Update Found! The DPDP Act has been modified.", last_checked, changes[:20]
    
    return "✓ No new updates. The DPDP Act is unchanged.", last_checked, []

# --- Streamlit UI ---
st.set_page_config(
    page_title="DPDP Compliance Checker", 
    page_icon="📜", 
    layout="wide"
)

# --- Custom Styling ---
st.markdown("""
    <style>
        .title-container {
            background-color: #00796b;
            padding: 15px;
            border-radius: 10px;
            color: white;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .btn-check {
            font-size: 18px;
            font-weight: bold;
            background-color: #FF5722 !important;
            color: white !important;
            padding: 10px 20px;
            border-radius: 8px;
            transition: 0.3s;
        }
        .btn-check:hover {
            background-color: #E64A19 !important;
        }
        .status-box {
            border-radius: 8px;
            padding: 12px;
            font-size: 16px;
            font-weight: bold;
            margin-top: 15px;
        }
        .update-box {
            background-color: #FF5252;
            color: white;
        }
        .no-update-box {
            background-color: #4CAF50;
            color: white;
        }
    </style>
""", unsafe_allow_html=True)

# --- UI Elements ---
st.markdown(
    '<div class="title-container">DPDP Compliance Checker (Official PDF)</div>', 
    unsafe_allow_html=True
)
st.write("This tool tracks changes in the **official DPDP Act PDF** from MeitY.")

if st.button("Check for Updates", help="Check for updates in the DPDP Act PDF", key="check_btn"):
    status_message, last_checked, changes = check_for_updates()
    
    # Timestamp
    st.markdown(f"**Last Checked:** {last_checked}")

    if "🔔" in status_message:
        st.markdown(
            f'<div class="status-box update-box">{status_message}</div>', 
            unsafe_allow_html=True
        )
        st.write("### Changes Detected:")
        st.code("\n".join(changes), language="diff")
    else:
        st.markdown(
            f'<div class="status-box no-update-box">{status_message}</div>', 
            unsafe_allow_html=True
        )