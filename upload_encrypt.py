import streamlit as st
import sqlite3
import os
import numpy as np
import cv2
from cryptography.fernet import Fernet
from PyPDF2 import PdfFileReader, PdfFileWriter

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Connect to SQLite database
conn = sqlite3.connect('securebyte.db')
c = conn.cursor()

# Create table for storing encrypted data
c.execute('''CREATE TABLE IF NOT EXISTS encrypted_data
             (id INTEGER PRIMARY KEY, name TEXT, path TEXT, size INTEGER, importance INTEGER)''')
conn.commit()

# Create a directory to store encrypted files
if not os.path.exists('encrypted_files'):
    os.makedirs('encrypted_files')

def encrypt_image(image_data, file_name):
    # Convert image data to numpy array
    nparr = np.frombuffer(image_data, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    # Encrypt the image by flipping it (simple example)
    encrypted_img = cv2.flip(img, 1)
    encrypted_path = os.path.join('encrypted_files', file_name)
    cv2.imwrite(encrypted_path, encrypted_img)
    return encrypted_path

def encrypt_video(video_data, file_name):
    # Custom encryption for video (simple example)
    encrypted_path = os.path.join('encrypted_files', file_name)
    with open(encrypted_path, 'wb') as f:
        f.write(video_data[::-1])  # Reverse the video data as a simple encryption
    return encrypted_path

def encrypt_pdf(pdf_data, file_name):
    # Encrypt PDF using PyPDF2
    pdf_reader = PdfFileReader(pdf_data)
    pdf_writer = PdfFileWriter()
    for page_num in range(pdf_reader.numPages):
        pdf_writer.addPage(pdf_reader.getPage(page_num))
    pdf_writer.encrypt(user_pwd='password', owner_pwd=None, use_128bit=True)
    encrypted_path = os.path.join('encrypted_files', file_name)
    with open(encrypted_path, 'wb') as f:
        pdf_writer.write(f)
    return encrypted_path

def show_page():
    st.title("Upload and Encrypt Files")
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        file_name = uploaded_file.name
        file_data = uploaded_file.read()
        file_size = len(file_data)
        importance = st.slider("Select the importance of the file", 1, 10)
        
        if file_name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            encrypted_path = encrypt_image(file_data, file_name)
        elif file_name.lower().endswith(('.mp4', '.avi', '.mov', '.wmv', '.flv')):
            encrypted_path = encrypt_video(file_data, file_name)
        elif file_name.lower().endswith('.pdf'):
            encrypted_path = encrypt_pdf(file_data, file_name)
        else:
            encrypted_data = cipher_suite.encrypt(file_data)
            encrypted_path = os.path.join('encrypted_files', file_name)
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
        
        c.execute("INSERT INTO encrypted_data (name, path, size, importance) VALUES (?, ?, ?, ?)",
                  (file_name, encrypted_path, file_size, importance))
        conn.commit()
        st.success("File uploaded and encrypted successfully!")