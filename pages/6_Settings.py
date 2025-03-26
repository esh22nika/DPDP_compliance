# import streamlit as st

# # Initialize session state if not already set
# if "user" not in st.session_state:
#     st.session_state.user = None

# if st.session_state.user is None:
#     st.warning("Please login/signup to access settings.")
# else:
#     st.title("Settings")

#     # Change Username
#     st.subheader("Change Username")
#     new_username = st.text_input("Enter new username", value=st.session_state.user["username"])
#     if st.button("Update Username"):
#         st.session_state.user["username"] = new_username
#         st.success("Username updated successfully!")

#     # Change Email
#     st.subheader("Change Email")
#     new_email = st.text_input("Enter new email", value=st.session_state.user.get("email", ""))
#     if st.button("Update Email"):
#         st.session_state.user["email"] = new_email
#         st.success("Email updated successfully!")

#     # Change Password
#     st.subheader("Change Password")
#     current_password = st.text_input("Current Password", type="password")
#     new_password = st.text_input("New Password", type="password")
#     confirm_password = st.text_input("Confirm New Password", type="password")
    
#     if st.button("Update Password"):
#         if current_password == st.session_state.user["password"]:  # Replace with proper password verification
#             if new_password == confirm_password:
#                 st.session_state.user["password"] = new_password
#                 st.success("Password updated successfully!")
#             else:
#                 st.error("New password and confirmation do not match.")
#         else:
#             st.error("Current password is incorrect.")

#     # Two-Factor Authentication (2FA)
#     st.subheader("Security")
#     enable_2fa = st.checkbox("Enable Two-Factor Authentication (2FA)")
#     if enable_2fa:
#         st.session_state.user["2fa_enabled"] = True
#         st.success("2FA Enabled!")
#     else:
#         st.session_state.user["2fa_enabled"] = False

#     # Profile Picture Upload
#     st.subheader("Profile Picture")
#     uploaded_file = st.file_uploader("Upload a new profile picture", type=["png", "jpg", "jpeg"])
#     if uploaded_file:
#         st.session_state.user["profile_pic"] = uploaded_file
#         st.image(uploaded_file, caption="Profile Picture Updated!", width=150)

#     # Dark Mode Toggle
#     st.subheader("Appearance")
#     dark_mode = st.toggle("Enable Dark Mode")
#     if dark_mode:
#         st.session_state.user["theme"] = "dark"
#         st.success("Dark mode enabled!")
#     else:
#         st.session_state.user["theme"] = "light"

#     # Logout Option
#     st.subheader("Logout")
#     if st.button("Logout"):
#         st.session_state.user = None
#         st.success("Logged out successfully! Please log in again.")

    


  
import streamlit as st

# Check if user is logged in
if "user" not in st.session_state:
    st.warning("Please login/signup to access settings.")
    st.stop()  # Stop execution if no user is logged in

st.title("Settings")

# Fetch user details from session state
user_data = st.session_state["user"]

# ---------------- USERNAME ----------------
st.subheader("Username")
st.text(user_data["username"])  # Display current username
if st.button("Edit Username"):
    st.session_state.edit_username = True

if st.session_state.get("edit_username", False):
    new_username = st.text_input("New Username", value=user_data["username"])
    if st.button("Save Username"):
        user_data["username"] = new_username
        st.session_state["user"] = user_data
        st.session_state.edit_username = False
        st.success("Username updated successfully!")


# ---------------- PASSWORD ----------------
st.subheader("Password")
st.text("********")  # Masked password display
if st.button("Edit Password"):
    st.session_state.edit_password = True

if st.session_state.get("edit_password", False):
    current_password = st.text_input("Current Password", type="password")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm New Password", type="password")

    if st.button("Save Password"):
        if current_password == user_data["password"]:  # Replace with actual password check
            if new_password == confirm_password:
                user_data["password"] = new_password
                st.session_state["user"] = user_data
                st.session_state.edit_password = False
                st.success("Password updated successfully!")
            else:
                st.error("New password and confirmation do not match.")
        else:
            st.error("Current password is incorrect.")

# ---------------- SECURITY SETTINGS ----------------
st.subheader("Security")
enable_2fa = st.checkbox("Enable Two-Factor Authentication (2FA)", user_data.get("2fa_enabled", False))
user_data["2fa_enabled"] = enable_2fa

# ---------------- ACCOUNT ACTIONS ----------------
st.subheader("Account Actions")
if st.button("Logout"):
    del st.session_state["user"]
    st.success("You have been logged out.")
    st.stop()

if st.button("Delete Account"):
    st.warning("Account deletion is permanent. Contact support to proceed.")

