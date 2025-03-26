import streamlit as st
import requests  # To make API calls
import cohere  # Cohere API

# # Initialize Cohere client
# API_KEY = "omwW07xRZRqPrIxSfx7FxYoaMQCB3cstWGXHYu0v"  # Replace with your actual API key
# co = cohere.Client(API_KEY)

# st.title("Compliance Roadmap")

# if "user" not in st.session_state or not st.session_state.user:
#     st.info("Please login/signup to access all features")
# else:
#     st.write("""
#     ### Step-by-Step Guide
#     1. Fix XSS vulnerabilities
#     2. Implement data encryption
#     3. Update privacy policy
#     4. Regular security audits
#     """)

#     # Chatbot Section
#     st.write("## Compliance Chatbot 🤖")
#     if "chat_history" not in st.session_state:
#         st.session_state.chat_history = []

#     for message in st.session_state.chat_history:
#         with st.chat_message(message["role"]):
#             st.write(message["content"])

#     user_input = st.chat_input("Ask me about compliance...")

#     if user_input:
#         st.session_state.chat_history.append({"role": "user", "content": user_input})

#         # API call to Cohere Chat
#         response = co.chat(message=user_input)
#         bot_response = response.text if response else "Sorry, I couldn't process that."

#         st.session_state.chat_history.append({"role": "assistant", "content": bot_response})
#         with st.chat_message("assistant"):
#             st.write(bot_response)

#     if st.button("Back to Dashboard"):
#         st.switch_page("main.py")



st.set_page_config(page_title="Compliance Chatbot", layout="wide")

floating_chat_button = """
    <style>
        .floating-chat {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: #ff6f00;
            color: white;
            border: none;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            font-size: 24px;
            cursor: pointer;
            box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
            z-index: 100;
        }
        .chat-popup {
            position: fixed;
            bottom: 80px;
            right: 20px;
            width: 320px;
            max-height: 400px;
            background: white;
            border-radius: 10px;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2);
            padding: 10px;
            overflow-y: auto;
            display: none;
            z-index: 200;
        }
        .show-chat {
            display: block !important;
        }
    </style>
    <button id="chatButton" class="floating-chat">💬</button>
    <div id="chatPopup" class="chat-popup">
        <h4>Compliance Chatbot 🤖</h4>
        <div id="chatMessages" style="max-height: 300px; overflow-y: auto;"></div>
        <input type="text" id="userMessage" placeholder="Type your message..." style="width: 100%; padding: 5px;">
        <button onclick="sendMessage()" style="width: 100%; margin-top: 5px;">Send</button>
    </div>
    <script>
        document.getElementById("chatButton").onclick = function() {
            document.getElementById("chatPopup").classList.toggle("show-chat");
        };

        async function sendMessage() {
            let message = document.getElementById("userMessage").value;
            if (!message) return;

            let chatBox = document.getElementById("chatMessages");
            chatBox.innerHTML += "<p><strong>You:</strong> " + message + "</p>";

            let response = await fetch('/send_message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: message })
            });
            let data = await response.json();
            chatBox.innerHTML += "<p><strong>Bot:</strong> " + data.reply + "</p>";

            document.getElementById("userMessage").value = "";
        }
    </script>
"""
st.markdown(floating_chat_button, unsafe_allow_html=True)
COHERE_API_KEY="omwW07xRZRqPrIxSfx7FxYoaMQCB3cstWGXHYu0v"
st.write("## Compliance Chatbot 🤖")
st.write("### How can I help You?")


if "user" not in st.session_state or not st.session_state.user:
    st.info("Please login/signup to access all features")
else:
    st.write("""
    ### Step-by-Step Guide
    1. Fix XSS vulnerabilities
    2. Implement data encryption
    3. Update privacy policy
    4. Regular security audits
    """)

# Backend Chatbot Logic
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []



user_input = st.chat_input("Ask me about compliance...")

if user_input:
    st.session_state.chat_history.append({"role": "user", "content": user_input})

    api_url = "https://api.cohere.com/v1/chat"
    headers = {
        "Authorization": f"Bearer {COHERE_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "message": user_input,
        "chat_history": [],
        "model": "command-r",
        "temperature": 0.8
    }

    response = requests.post(api_url, json=payload, headers=headers)
    bot_response = response.json().get("text", "Sorry, I couldn't process that.")

    st.session_state.chat_history.append({"role": "assistant", "content": bot_response})

    with st.expander("💬 Open Chat"):
        for msg in st.session_state.chat_history:
            role = "👤 You" if msg["role"] == "user" else "🤖 Bot"
            st.write(f"**{role}:** {msg['content']}")



import streamlit as st
from together import Together

# Initialize Together API client
client = Together(api_key="tgp_v1_wR2Ipu5B-6jXNfljNiZavXeRksEir41Jp-3-vQK075E")  # Get a free API key from https://www.together.xyz/

# Function to read the final report file
def read_final_report(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()

# Function to generate checklist using Together AI
def generate_checklist(report_text):
    response = client.chat.completions.create(
        model="meta-llama/Llama-3.3-70B-Instruct-Turbo",  # Free model
        messages=[{"role": "user", "content": f"Generate a compliance checklist from this report:\n\n{report_text}"}]
    )
    return response.choices[0].message.content

# Streamlit UI
st.title("Compliance Checklist Generator")

# File Upload
uploaded_file = st.file_uploader("Upload Final Report (TXT file)", type=["txt"])

if uploaded_file is not None:
    # Read file content
    report_text = uploaded_file.read().decode("utf-8")

    # Generate checklist
    if st.button("Generate Checklist"):
        checklist = generate_checklist(report_text)
        st.subheader("Generated Checklist:")
        st.write(checklist)





#tgp_v1_wR2Ipu5B-6jXNfljNiZavXeRksEir41Jp-3-vQK075E
#6c9631e062a1e28df31f448a90a7ca446be81b671de82c1f89943edd8c62e12f