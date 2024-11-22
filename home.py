import streamlit as st
import random
import string
import pyperclip

# Function to generate a random password
def generate_password(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    characters = ""
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation

    if not characters:
        return "Please select at least one character set."

    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Function to display the home page
def show_home_page():
    st.title("SecureByte Password Manager")
    st.write("Welcome to SecureByte, your secure solution for managing passwords.")

    st.header("Documentation")
    st.write("""
    **SecureByte Password Manager** is a secure application designed to manage and store passwords. 
    It uses advanced encryption techniques to ensure the safety of your data. The application is built 
    using Streamlit for the user interface and SQLite for database management. It also includes various 
    algorithms for password strength analysis and similarity checks.
    """)

    st.header("Features")
    st.write("""
    - **Create, Load, and Delete Databases**: Manage multiple password databases with ease.
    - **Add, View, Edit, and Delete Password Entries**: Perform CRUD operations on password entries.
    - **Password Encryption**: Encrypt passwords using AES-CBC encryption.
    - **Password Strength Analysis**: Analyze password strength using the knapsack algorithm and zxcvbn library.
    - **Password Similarity Check**: Compare passwords using the Longest Common Subsequence (LCS) algorithm.
    """)

    st.header("Utility Tools")
    st.write("Use the tools below to enhance your password management experience.")

    # Password Generator Tool
    st.subheader("Password Generator")
    length = st.slider("Select Password Length", min_value=8, max_value=32, value=12)
    use_uppercase = st.checkbox("Include Uppercase Letters", value=True)
    use_lowercase = st.checkbox("Include Lowercase Letters", value=True)
    use_digits = st.checkbox("Include Digits", value=True)
    use_special = st.checkbox("Include Special Characters", value=True)

    if st.button("Generate Password"):
        password = generate_password(length, use_uppercase, use_lowercase, use_digits, use_special)
        st.write(f"Generated Password: `{password}`")
        if st.button("Copy Password"):
            pyperclip.copy(password)
            st.success("Password copied to clipboard!")

    # Placeholder for additional tools
    st.subheader("More Tools Coming Soon!")
    st.write("Stay tuned for more utility tools to help you manage your passwords securely.")

# Main Application
def main():
    show_home_page()

if __name__ == "__main__":
    main()