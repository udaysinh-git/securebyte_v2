import streamlit as st
import sqlite3

def show_page():
    st.title("Explore Encrypted Files")

    # Create a new SQLite connection
    conn = sqlite3.connect('securebyte.db')
    c = conn.cursor()

    # Fetch all encrypted files from the database
    c.execute("SELECT name, size, importance FROM encrypted_data")
    files = c.fetchall()
    conn.close()

    if files:
        st.write("### Images")
        for file in files:
            if file[0].lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                st.write(f"**Name:** {file[0]}, **Size:** {file[1]} bytes, **Importance:** {file[2]}")

        st.write("### Videos")
        for file in files:
            if file[0].lower().endswith(('.mp4', '.avi', '.mov', '.wmv', '.flv')):
                st.write(f"**Name:** {file[0]}, **Size:** {file[1]} bytes, **Importance:** {file[2]}")

        st.write("### Documents")
        for file in files:
            if file[0].lower().endswith(('.pdf', '.doc', '.docx', '.txt')):
                st.write(f"**Name:** {file[0]}, **Size:** {file[1]} bytes, **Importance:** {file[2]}")

        st.write("### Passwords")
        for file in files:
            if file[0].lower().endswith('.pwd'):
                st.write(f"**Name:** {file[0]}, **Size:** {file[1]} bytes, **Importance:** {file[2]}")
    else:
        st.write("No encrypted files found.")