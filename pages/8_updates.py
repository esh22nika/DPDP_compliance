import streamlit as st
import requests
from bs4 import BeautifulSoup
import os
import difflib
from datetime import datetime
from plyer import notification
from PIL import Image

# DPDP Compliance Website URL
DPDP_URL = "https://www.dpdpa.in/"
TEXT_FILE = "dpdp_data.txt"
HEADERS = {"User-Agent": "Mozilla/5.0"}

# --- Function Definitions ---
def fetch_dpdp_data():
    """Scrapes text from the DPDP website."""
    response = requests.get(DPDP_URL, headers=HEADERS)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.get_text(separator="\n", strip=True)
    return None

def save_text_to_file(text, filename):
    """Saves text data to a file."""
    with open(filename, "w", encoding="utf-8") as file:
        file.write(text)

def load_previous_text(filename):
    """Loads previously stored text data."""
    return open(filename, "r", encoding="utf-8").read() if os.path.exists(filename) else None

def send_notification(title, message):
    """Sends a desktop notification when updates are found."""
    notification.notify(title=title, message=message, app_name="DPDP Compliance Checker", timeout=10)

def check_for_updates():
    """Checks if the website content has changed."""
    new_text = fetch_dpdp_data()
    last_checked = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if new_text:
        old_text = load_previous_text(TEXT_FILE)
        if old_text is None:
            save_text_to_file(new_text, TEXT_FILE)
            return "ℹ *First-time check. Data saved.*", last_checked, []

        diff = list(difflib.ndiff(old_text.splitlines(), new_text.splitlines()))
        changes = [line for line in diff if line.startswith("+ ") or line.startswith("- ")]

        if changes:
            save_text_to_file(new_text, TEXT_FILE)
            send_notification("DPDP Update Alert!", "New changes detected on the DPDP website!")
            return "🔔 *Update Found!* The DPDP website has been updated.", last_checked, changes[:10]
    
    return " No new updates. Everything is up to date.", last_checked, []

# --- Streamlit UI ---
st.set_page_config(page_title="DPDP Compliance Checker", page_icon="📜", layout="wide")

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
st.markdown('<div class="title-container"> DPDP Compliance Checker</div>', unsafe_allow_html=True)
st.write(" This tool *automatically tracks changes* on the DPDP website and alerts you to updates.")

if st.button(" Check for Updates", help="Click to check if the DPDP website has changed!", key="check_btn"):
    status_message, last_checked, changes = check_for_updates()
    
    # Timestamp
    st.markdown(f" *Last Checked:* {last_checked}")

    if "🔔" in status_message:
        st.markdown(f'<div class="status-box update-box">{status_message}</div>', unsafe_allow_html=True)
        st.write("###  *New Changes Found:*")
    else:
        st.markdown(f'<div class="status-box no-update-box">{status_message}</div>', unsafe_allow_html=True)