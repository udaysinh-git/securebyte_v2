import streamlit as st
from streamlit_option_menu import option_menu

# Set page configuration
st.set_page_config(page_title="SecureByte", layout="wide")

with st.sidebar:
    selected = option_menu(
        "Main Menu",
        ["Home", "Upload and Encrypt", "Search Files", "Optimize Storage", "Explore", "Password Manager"],
        icons=["house", "cloud-upload", "search", "bar-chart", "folder", "key"],
        menu_icon="cast",
        default_index=0,
    )

if selected == "Home":
    st.title("Welcome to SecureByte")
    st.write("A secure application to encrypt and store your data.")
elif selected == "Upload and Encrypt":
    import upload_encrypt
    upload_encrypt.show_page()
elif selected == "Search Files":
    import search_files
    search_files.show_page()
elif selected == "Optimize Storage":
    import optimize_storage
    optimize_storage.show_page()
elif selected == "Explore":
    import explore
    explore.show_page()
elif selected == "Password Manager":
    import password_manager
    password_manager.show_page()