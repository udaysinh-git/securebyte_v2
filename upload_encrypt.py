import streamlit as st
import sqlite3
import os
import logging
import tempfile
import uuid
from sanzan import Sanzan  # Assuming Sanzan is installed and available

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Connect to SQLite database
conn = sqlite3.connect('securebyte.db', check_same_thread=False)
c = conn.cursor()

# Create table for storing encrypted data
c.execute('''
CREATE TABLE IF NOT EXISTS encrypted_data (
    id INTEGER PRIMARY KEY, 
    name TEXT, 
    path TEXT, 
    size INTEGER, 
    importance INTEGER, 
    password TEXT, 
    title TEXT, 
    description TEXT
)
''')
conn.commit()

# Create a directory to store encrypted files
ENCRYPTED_DIR = 'encrypted_files'
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

def encrypt_video(video_data, file_name):
    """Encrypt a video using Sanzan."""
    try:
        # Save the video to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as temp_file:
            temp_file.write(video_data)
            temp_file_path = temp_file.name

        # Encrypt the video using Sanzan
        encrypted_path = os.path.join(ENCRYPTED_DIR, file_name)
        Sanzan.encrypt(temp_file_path, encrypted_path)

        # Clean up the temporary file
        os.remove(temp_file_path)

        return encrypted_path
    except Exception as e:
        logging.error(f"Video encryption failed: {e}")
        return None

def validate_inputs(password):
    """Validate user inputs."""
    if not password:
        st.error("Password cannot be empty!")
        return False
    return True

def show_page():
    st.title("SecureByte - Video Encryption Platform")

    # File uploader
    file_uploader_key = f"file_uploader_{uuid.uuid4().hex}"
    logging.info(f"Generated file uploader key: {file_uploader_key}")

    uploaded_file = st.file_uploader("Upload a video file to encrypt", type=["mp4", "avi", "mov", "wmv", "flv"], key=file_uploader_key)
    logging.info(f"Uploaded file: {uploaded_file}")

    if uploaded_file is None:
        logging.info("No file uploaded")
        st.warning("Please upload a video file to encrypt.")
        return

    if uploaded_file is not None:
        logging.info("File uploaded")
        st.write("File uploaded successfully!")
        file_name = uploaded_file.name
        video_data = uploaded_file.read()
        file_size = len(video_data)
        logging.info(f"File name: {file_name}, File size: {file_size}")

        # Metadata inputs
        importance = st.slider("Select the importance of the file (1 - Low, 10 - High)", 1, 10)
        password = st.text_input("Set a password for the file", type="password")
        title = st.text_input("Title", value=file_name)
        description = st.text_area("Description (optional)")

        if st.button("Encrypt and Save"):
            if not validate_inputs(password):
                return

            try:
                # Display the uploaded video
                st.video(video_data, format="video/mp4", start_time=0)

                # Encrypt the video
                encrypted_path = encrypt_video(video_data, file_name)

                # Save details to the database
                if encrypted_path:
                    c.execute(
                        "INSERT INTO encrypted_data (name, path, size, importance, password, title, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (file_name, encrypted_path, file_size, importance, password, title, description)
                    )
                    conn.commit()

                    st.success(f"Video '{file_name}' encrypted and saved successfully!")
                    st.write(f"Encrypted file path: `{encrypted_path}`")
                else:
                    st.error("Encryption failed. Please check the logs.")

            except Exception as e:
                logging.error(f"An error occurred during encryption: {e}")
                st.error(f"An error occurred during encryption: {e}")

# Run the app
show_page()