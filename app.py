import streamlit as st
from streamlit_option_menu import option_menu

# Set page configuration
st.set_page_config(page_title="SecureByte", layout="wide")

with st.sidebar:
    selected = option_menu(
        "Main Menu",
        ["Home","Password Manager"],
        icons=["house", "key"],
        menu_icon="cast",
        default_index=0,
    )

if selected == "Home":
    import home
    home.show_home_page()
elif selected == "Password Manager":
    import password_manager
    password_manager.show_page()