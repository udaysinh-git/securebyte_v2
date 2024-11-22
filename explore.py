import streamlit as st
import sqlite3

def merge_sort(arr):
    if len(arr) > 1:
        mid = len(arr) // 2
        L = arr[:mid]
        R = arr[mid:]

        merge_sort(L)
        merge_sort(R)

        i = j = k = 0

        while i < len(L) and j < len(R):
            if L[i][0].lower() < R[j][0].lower():
                arr[k] = L[i]
                i += 1
            else:
                arr[k] = R[j]
                j += 1
            k += 1

        while i < len(L):
            arr[k] = L[i]
            i += 1
            k += 1

        while j < len(R):
            arr[k] = R[j]
            j += 1
            k += 1

def show_page():
    st.title("Explore Encrypted Files")

    # Create a new SQLite connection
    conn = sqlite3.connect('securebyte.db')
    c = conn.cursor()

    # Fetch all encrypted files from the database
    c.execute("SELECT name, size, importance, title, description FROM encrypted_data")
    files = c.fetchall()
    conn.close()

    if files:
        merge_sort(files)  # Sort files using merge sort

        st.write("### Images")
        for file in files:
            if file[0].lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                st.write(f"**Name:** {file[0]}, **Size:** {file[1]} bytes, **Importance:** {file[2]}, **Title:** {file[3]}, **Description:** {file[4]}")

        st.write("### Videos")
        for file in files:
            if file[0].lower().endswith(('.mp4', '.avi', '.mov', '.wmv', '.flv')):
                st.write(f"**Name:** {file[0]}, **Size:** {file[1]} bytes, **Importance:** {file[2]}, **Title:** {file[3]}, **Description:** {file[4]}")

        st.write("### Documents")
        for file in files:
            if file[0].lower().endswith(('.pdf', '.doc', '.docx', '.txt')):
                st.write(f"**Name:** {file[0]}, **Size:** {file[1]} bytes, **Importance:** {file[2]}, **Title:** {file[3]}, **Description:** {file[4]}")
    else:
        st.write("No encrypted files found.")

show_page()