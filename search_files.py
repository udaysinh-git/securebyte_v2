import streamlit as st
import sqlite3
from cryptography.fernet import Fernet

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Connect to SQLite database
conn = sqlite3.connect('securebyte.db')
c = conn.cursor()

def decrypt_data(data):
    return cipher_suite.decrypt(data)

def show_page():
    st.title("Search Files")
    search_query = st.text_input("Enter the file name to search")
    if search_query:
        c.execute("SELECT name, data FROM encrypted_data WHERE name LIKE ?", ('%' + search_query + '%',))
        results = c.fetchall()
        if results:
            for result in results:
                st.write(f"File Name: {result[0]}")
                if st.button(f"Decrypt {result[0]}"):
                    decrypted_data = decrypt_data(result[1])
                    st.download_button(label="Download Decrypted File", data=decrypted_data, file_name=result[0])
        else:
            st.write("No files found.")