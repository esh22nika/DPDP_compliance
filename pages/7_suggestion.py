import streamlit as st
import requests
import cohere 

st.title("Suggestions for Privacy Compliance")

st.write("Here you can find recommendations to improve compliance with DPDP.")



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
        <h4>Compliance Chatbot </h4>
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



if "user" not in st.session_state or not st.session_state.user:
    st.info("Please login/signup to access all features")
else:
    suggestions = [
    "Ensure your Privacy Policy includes a clear Data Retention Policy.",
    "Add a section explaining user rights regarding their data.",
    "Provide an easy opt-out mechanism for data collection."
]

for suggestion in suggestions:
    st.info(suggestion)
# Backend Chatbot Logic
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []



user_input = st.chat_input("Get Some Suggestions...")

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

    with st.expander("Open Chat"):
        for msg in st.session_state.chat_history:
            role = "You" if msg["role"] == "user" else "Bot"
            st.write(f"*{role}:* {msg['content']}")