import streamlit as st
import sqlite3
import hashlib

def create_users_table():
    conn = sqlite3.connect('database/users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT,
                  username TEXT UNIQUE,
                  password TEXT)''')
    conn.commit()
    conn.close()

def signup():
    with st.form("Signup"):
        name = st.text_input("Full Name")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Sign Up")
        
        if submit:
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            try:
                conn = sqlite3.connect('database/users.db')
                c = conn.cursor()
                c.execute("INSERT INTO users (name, username, password) VALUES (?, ?, ?)",
                         (name, username, hashed_pw))
                conn.commit()
                st.success("Account created successfully! Please login.")
            except sqlite3.IntegrityError:
                st.error("Username already exists!")
            finally:
                conn.close()

def login():
    with st.form("Login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            conn = sqlite3.connect('database/users.db')
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_pw))
            user = c.fetchone()
            conn.close()
            
            if user:
                st.session_state.user = {
                    "id": user[0],
                    "name": user[1],
                    "username": user[2]
                }
                st.rerun()
            else:
                st.error("Invalid credentials")