import streamlit as st
import sqlite3
from cryptography.fernet import Fernet
import uuid

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Connect to SQLite database
conn = sqlite3.connect('securebyte.db')
c = conn.cursor()

def decrypt_data(data):
    return cipher_suite.decrypt(data)

def binary_search(arr, x):
    l, r = 0, len(arr) - 1
    while l <= r:
        mid = l + (r - l) // 2
        if arr[mid][0] == x:
            return mid
        elif arr[mid][0] < x:
            l = mid + 1
        else:
            r = mid - 1
    return -1

def show_page():
    st.title("Search Files")
    unique_key = str(uuid.uuid4())
    search_query = st.text_input("Enter the file name, title, or description to search", key=unique_key)
    if search_query:
        c.execute("SELECT name, path, password FROM encrypted_data WHERE name LIKE ? OR title LIKE ? OR description LIKE ?", 
                  ('%' + search_query + '%', '%' + search_query + '%', '%' + search_query + '%'))
        results = c.fetchall()
        results.sort(key=lambda x: x[0])  # Sort results by file name for binary search

        if results:
            index = binary_search(results, search_query)
            if index != -1:
                result = results[index]
                st.write(f"File Name: {result[0]}")
                if st.button(f"Decrypt {result[0]}"):
                    with open(result[1], 'rb') as f:
                        encrypted_data = f.read()
                    decrypted_data = decrypt_data(encrypted_data)
                    st.download_button(label="Download Decrypted File", data=decrypted_data, file_name=result[0])
            else:
                st.write("No files found.")
        else:
            st.write("No files found.")

show_page()