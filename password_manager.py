import streamlit as st
import sqlite3
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import hashlib
import json
import plotly.graph_objects as go
from zxcvbn import zxcvbn

# Constants
BASE_DIR = "password_databases"
SALT_FILE = "salt.key"
SALT_SIZE = 16

# Ensure the base directory exists
os.makedirs(BASE_DIR, exist_ok=True)

# Generate or load salt
if not os.path.exists(SALT_FILE):
    salt = os.urandom(SALT_SIZE)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
else:
    with open(SALT_FILE, "rb") as f:
        salt = f.read()

# Encryption Utilities
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key using PBKDF2."""
    return PBKDF2(password, salt, dkLen=32, count=1000000)

def encrypt(raw: bytes, key: bytes) -> bytes:
    """Encrypt data with AES-CBC."""
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(raw)
    return iv + cipher.encrypt(padded_data)

def decrypt(enc: bytes, key: bytes) -> bytes:
    """Decrypt AES-CBC encrypted data."""
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[AES.block_size:]))

def pad(data: bytes) -> bytes:
    """Pad data to match AES block size."""
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """Remove padding."""
    pad_len = data[-1]
    return data[:-pad_len]

# Database Functions
def create_database(name: str, category: str, password: str):
    """Create a new database."""
    file_path = os.path.join(BASE_DIR, f"{name}.db")
    if os.path.exists(file_path):
        raise ValueError("Database with this name already exists.")
    
    conn = sqlite3.connect(file_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, name TEXT, description TEXT, encrypted_password TEXT)"
    )
    conn.commit()
    conn.close()

    metadata = {"category": category}
    with open(file_path + ".meta", "w") as meta_file:
        json.dump(metadata, meta_file)

    # Store the password in a JSON file (temporary solution)
    password_data = {name: password}
    with open("./password_databases/passwords.json", "a") as password_file:
        json.dump(password_data, password_file)
        password_file.write("\n")

def load_database(file_path: str, password: str):
    """Load a database into memory."""
    if not os.path.exists(file_path):
        raise FileNotFoundError("Database file not found.")
    
    key = derive_key(password, salt)
    conn = sqlite3.connect(file_path)
    return conn, key

def save_database(conn: sqlite3.Connection):
    """Save the in-memory database to a file."""
    conn.commit()

def delete_database(name: str, password: str):
    """Delete a database and its metadata after verifying the password."""
    file_path = os.path.join(BASE_DIR, f"{name}.db")
    meta_file_path = file_path + ".meta"
    
    # Load the stored passwords from the JSON file
    with open("./password_databases/passwords.json", "r") as password_file:
        stored_passwords = {}
        for line in password_file:
            stored_passwords.update(json.loads(line))
    
    # Verify the password
    if stored_passwords.get(name) != password:
        raise ValueError("Incorrect password.")
    
    # Proceed with deletion if password is correct
    if os.path.exists(file_path):
        os.remove(file_path)
    if os.path.exists(meta_file_path):
        os.remove(meta_file_path)

# UI Functions
def show_databases():
    """List all existing databases."""
    databases = [
        f[:-3] for f in os.listdir(BASE_DIR) if f.endswith(".db")
    ]
    metadata = {}
    for db in databases:
        meta_path = os.path.join(BASE_DIR, db + ".meta")
        if os.path.exists(meta_path):
            with open(meta_path, "r") as meta_file:
                metadata[db] = json.load(meta_file)
    return databases, metadata

def manage_database_ui():
    """Manage multiple password databases."""
    st.sidebar.title("SecureByte - Manage Password Databases")
    databases, metadata = show_databases()

    # Display existing databases
    st.sidebar.header("Your Databases")
    for db in databases:
        category = metadata.get(db, {}).get('category', 'Uncategorized')
        st.sidebar.write(f"**{db}** ({category})")

    # Options to add or delete databases
    st.sidebar.header("Manage Databases")
    create_new = st.sidebar.checkbox("Create New Database")
    delete_existing = st.sidebar.checkbox("Delete a Database")

    if create_new:
        st.subheader("Create a New Database")
        name = st.text_input("Database Name")
        category = st.text_input("Category (optional)")
        password = st.text_input("Set Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Create Database"):
            if not name or not password:
                st.error("Name and password are required.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            else:
                try:
                    create_database(name, category, password)
                    st.success(f"Database '{name}' created successfully!")
                except Exception as e:
                    st.error(f"Error: {e}")

    if delete_existing:
        st.subheader("Delete a Database")
        db_to_delete = st.selectbox("Select Database to Delete", databases)
        password = st.text_input("Enter Password to Confirm Deletion", type="password")
        
        if st.button("Delete Database"):
            try:
                delete_database(db_to_delete, password)
                st.success(f"Database '{db_to_delete}' deleted successfully!")
            except Exception as e:
                st.error(f"Error: {e}")

def access_database_ui():
    """Access and manage a specific database."""
    st.title("Access a Password Database")
    databases, _ = show_databases()

    selected_db = st.selectbox("Select a Database", databases)
    password = st.text_input("Enter Password to Unlock", type="password")

    if st.button("Unlock Database"):
        file_path = os.path.join(BASE_DIR, f"{selected_db}.db")
        try:
            # Load the stored passwords from the JSON file
            with open("./password_databases/passwords.json", "r") as password_file:
                stored_passwords = {}
                for line in password_file:
                    stored_passwords.update(json.loads(line))

            # Verify the password
            if stored_passwords.get(selected_db) == password:
                conn, key = load_database(file_path, password)
                st.session_state["db_unlocked"] = True
                st.session_state["file_path"] = file_path
                st.session_state["key"] = key
                st.session_state["selected_db"] = selected_db
                st.success(f"Database '{selected_db}' unlocked successfully!")
            else:
                st.error("Incorrect password. Please try again.")
        except Exception as e:
            st.error(f"Failed to unlock the database: {e}")

def lcs(X, Y):
    """Compute the Longest Common Subsequence (LCS) of two strings."""
    m = len(X)
    n = len(Y)
    L = [[None] * (n + 1) for i in range(m + 1)]

    for i in range(m + 1):
        for j in range(n + 1):
            if i == 0 or j == 0:
                L[i][j] = 0
            elif X[i - 1] == Y[j - 1]:
                L[i][j] = L[i - 1][j - 1] + 1
            else:
                L[i][j] = max(L[i - 1][j], L[i][j - 1])

    return L[m][n]

def compare_passwords_lcs(password, entries, key):
    """Compare a password with existing entries using LCS."""
    similarities = []
    for entry in entries:
        decrypted_password = decrypt(base64.b64decode(entry[3]), key).decode('utf-8')
        lcs_length = lcs(password, decrypted_password)
        similarity_percentage = (lcs_length / max(len(password), len(decrypted_password))) * 100
        similarities.append((entry[1], similarity_percentage))
    return similarities

def plot_similarities(similarities):
    """Plot the similarities using Plotly."""
    names = [entry[0] for entry in similarities]
    percentages = [entry[1] for entry in similarities]

    fig = go.Figure(data=[go.Bar(
        x=percentages,
        y=names,
        orientation='h',
        marker=dict(color='skyblue')
    )])

    fig.update_layout(
        title='Password Similarities',
        xaxis_title='Similarity Percentage',
        yaxis_title='Password Entries'
    )

    st.plotly_chart(fig)



# Define password characteristics and their weights
characteristics = {
    "length": 10,
    "uppercase": 5,
    "lowercase": 5,
    "digits": 5,
    "special": 5
}

# Define the maximum weight (knapsack capacity)
max_weight = 20

def knapsack(characteristics, max_weight):
    n = len(characteristics)
    items = list(characteristics.items())
    dp = [[0 for _ in range(max_weight + 1)] for _ in range(n + 1)]

    for i in range(1, n + 1):
        for w in range(1, max_weight + 1):
            char_name, char_weight = items[i - 1]
            if char_weight <= w:
                dp[i][w] = max(dp[i - 1][w], dp[i - 1][w - char_weight] + char_weight)
            else:
                dp[i][w] = dp[i - 1][w]

    # Find the selected characteristics
    selected_chars = []
    w = max_weight
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i - 1][w]:
            selected_chars.append(items[i - 1][0])
            w -= items[i - 1][1]

    return selected_chars, dp[n][max_weight]

def check_password_strength(password):
    """Check the strength of a password using the knapsack algorithm."""
    length = len(password)
    uppercase = sum(1 for c in password if c.isupper())
    lowercase = sum(1 for c in password if c.islower())
    digits = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum())

    # Define the characteristics and their weights
    characteristics = {
        "length": min(length, 10),
        "uppercase": min(uppercase, 5),
        "lowercase": min(lowercase, 5),
        "digits": min(digits, 5),
        "special": min(special, 5)
    }

    # Define the maximum weight (knapsack capacity)
    max_weight = 20

    # Get the optimal set of characteristics
    selected_chars, total_weight = knapsack(characteristics, max_weight)

    return selected_chars, total_weight

def check_similarities_ui():
    """Check password similarities and analyze password strength."""
    st.subheader("Check Password Similarities")
    password = st.text_input("Enter Password to Check (leave empty to compare all passwords)", type="password", help="Enter the password to check for similarities.", key="check_similarities_password")
    
    if st.button("Check Similarities", key="check_similarities_button"):
        if "file_path" in st.session_state and "key" in st.session_state:
            file_path = st.session_state["file_path"]
            key = st.session_state["key"]
            conn, _ = load_database(file_path, key)
            cursor = conn.execute("SELECT id, name, description, encrypted_password FROM passwords")
            rows = cursor.fetchall()
            if rows:
                if password:
                    # Compare the input password with all existing passwords
                    similarities = compare_passwords_lcs(password, rows, key)
                    plot_similarities(similarities)
                    st.write("### Similarity Results")
                    for name, similarity in similarities:
                        st.write(f"**{name}**: {similarity:.2f}% similar")
                    
                    # Password strength analysis using knapsack
                    selected_chars, total_weight = check_password_strength(password)
                    st.write("### Password Strength Analysis")
                    st.write(f"**Selected Characteristics**: {', '.join(selected_chars)}")
                    st.write(f"**Total Weight**: {total_weight}")

                    # Password strength analysis using zxcvbn
                    strength = zxcvbn(password)
                    st.write(f"**Score**: {strength['score']}/4")
                    st.write("**Feedback**:")
                    for suggestion in strength['feedback']['suggestions']:
                        st.write(f"- {suggestion}")
                    
                    # Display password strength with colors and emojis
                    strength_color = ["red", "orange", "yellow", "lightgreen", "green"]
                    strength_emoji = ["😡", "😟", "😐", "😊", "😃"]
                    st.markdown(f"**Strength**: <span style='color:{strength_color[strength['score']]}'>**{strength_emoji[strength['score']]} {strength['score']}/4**</span>", unsafe_allow_html=True)
                else:
                    # Compare all existing passwords with each other
                    all_similarities = []
                    progress_bar = st.progress(0)
                    total_comparisons = len(rows) * (len(rows) - 1) // 2
                    comparison_count = 0

                    for i, entry1 in enumerate(rows):
                        for entry2 in rows[i+1:]:
                            decrypted_password1 = decrypt(base64.b64decode(entry1[3]), key).decode('utf-8')
                            decrypted_password2 = decrypt(base64.b64decode(entry2[3]), key).decode('utf-8')
                            lcs_length = lcs(decrypted_password1, decrypted_password2)
                            similarity_percentage = (lcs_length / max(len(decrypted_password1), len(decrypted_password2))) * 100
                            all_similarities.append(similarity_percentage)
                            comparison_count += 1
                            progress_bar.progress(comparison_count / total_comparisons)
                    
                    # Calculate the average similarity percentage
                    if all_similarities:
                        average_similarity = sum(all_similarities) / len(all_similarities)
                    else:
                        average_similarity = 0

                    # Display the average similarity percentage
                    st.write("### Overall Similarity Score")
                    st.write(f"**Average Similarity**: {average_similarity:.2f}%")

                    # Display a message based on the similarity score
                    if average_similarity > 50:
                        st.markdown(f"<span style='color:red'>Your passwords are too similar! Consider using more unique passwords.</span>", unsafe_allow_html=True)
                    elif average_similarity > 20:
                        st.markdown(f"<span style='color:orange'>Your passwords have some similarities. Try to make them more unique.</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<span style='color:green'>Your passwords are sufficiently unique.</span>", unsafe_allow_html=True)
            else:
                st.info("No entries found in the database.")
        else:
            st.error("No database is currently unlocked.")

def manage_entries_ui():
    """Manage entries in an unlocked database."""
    file_path = st.session_state["file_path"]
    key = st.session_state["key"]

    # Re-establish the connection within the same thread
    conn, _ = load_database(file_path, key)

    st.header(f"Manage Password Entries in '{st.session_state['selected_db']}'")
    option = st.radio("Choose an option", ["Add Entry", "View Entries", "Edit Entry", "Delete Entry", "Check Similarities"])

    if option == "Add Entry":
        st.subheader("Add a New Password Entry")
        st.markdown(
            """
            Use this section to add a new password entry. Provide the required details below.
            """
        )
        
        # Create a form to group input fields and prevent UI reset
        with st.form(key='add_entry_form'):
            # Step 1: Entry Name
            name = st.text_input("Entry Name (required)", help="Provide a name to identify this entry.", key="add_entry_name")
            
            # Step 2: Optional Description
            with st.expander("Add a Description (optional)"):
                description = st.text_area("Description", help="Add any notes or details about this entry.", key="add_entry_description")
            
            # Step 3: Password
            password = st.text_input("Password (required)", type="password", help="Enter the password for this entry.", key="add_entry_password")

            # Step 4: Submit Button
            submit_button = st.form_submit_button("Add Entry")

            if submit_button:
                if not name or not password:
                    st.error("Name and Password are required!")
                else:
                    try:
                        encrypted_password = base64.b64encode(encrypt(password.encode(), key)).decode('utf-8')
                        conn.execute(
                            "INSERT INTO passwords (name, description, encrypted_password) VALUES (?, ?, ?)",
                            (name, description, encrypted_password),
                        )
                        save_database(conn)
                        st.success(f"Entry '{name}' added successfully!")
                        # Clear input fields
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error saving entry: {e}")

    elif option == "View Entries":
        st.subheader("View All Password Entries")
        # Query the database for entries
        cursor = conn.execute("SELECT id, name, description, encrypted_password FROM passwords")
        rows = cursor.fetchall()
    
        if rows:
            for row in rows:
                decrypted_password = decrypt(base64.b64decode(row[3]), key).decode('utf-8')
                with st.expander(f"**{row[1]}**"):
                    st.write(f"**Description**: {row[2]}")
                    st.write(f"**Password**: {decrypted_password}")
                    if st.button("Copy Password", key=f"copy_{row[0]}"):
                        st.session_state[f"copied_password_{row[0]}"] = decrypted_password
                        st.success(f"Password for '{row[1]}' copied to clipboard!")
        else:
            st.info("No entries found in the database.")

    elif option == "Edit Entry":
        st.subheader("Edit a Password Entry")
        # Query the database for entries
        cursor = conn.execute("SELECT id, name, description, encrypted_password FROM passwords")
        rows = cursor.fetchall()

        if rows:
            entries = {row[1]: row for row in rows}
            selected_entry = st.selectbox("Select Entry to Edit", list(entries.keys()), key="edit_entry_select")
            entry = entries[selected_entry]

            with st.form(key='edit_entry_form'):
                name = st.text_input("Entry Name (required)", value=entry[1], help="Provide a name to identify this entry.", key="edit_entry_name")
                description = st.text_area("Description", value=entry[2], help="Add any notes or details about this entry.", key="edit_entry_description")
                password = st.text_input("Password (required)", type="password", value=decrypt(base64.b64decode(entry[3]), key).decode('utf-8'), help="Enter the password for this entry.", key="edit_entry_password")
                submit_button = st.form_submit_button("Update Entry")

                if submit_button:
                    if not name or not password:
                        st.error("Name and Password are required!")
                    else:
                        try:
                            encrypted_password = base64.b64encode(encrypt(password.encode(), key)).decode('utf-8')
                            conn.execute(
                                "UPDATE passwords SET name = ?, description = ?, encrypted_password = ? WHERE id = ?",
                                (name, description, encrypted_password, entry[0]),
                            )
                            save_database(conn)
                            st.success(f"Entry '{name}' updated successfully!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error updating entry: {e}")

        else:
            st.info("No entries to edit.")

    elif option == "Delete Entry":
        st.subheader("Delete a Password Entry")
        # Query the database for entries
        cursor = conn.execute("SELECT id, name FROM passwords")
        rows = cursor.fetchall()

        if rows:
            entries = {row[1]: row[0] for row in rows}
            selected_entry = st.selectbox("Select Entry to Delete", list(entries.keys()), key="delete_entry_select")

            if st.button("Delete Entry", key="delete_entry_button"):
                conn.execute("DELETE FROM passwords WHERE id = ?", (entries[selected_entry],))
                save_database(conn)
                st.success(f"Entry '{selected_entry}' deleted successfully!")
        else:
            st.info("No entries to delete.")

    elif option == "Check Similarities":
        check_similarities_ui()

    # Save changes to the database on UI interaction
    save_database(conn)

    # Add a button to close the current database
    if st.button("Close Database", key="close_database_button"):
        # Reset session state to lock the database
        st.session_state["db_unlocked"] = False
        st.session_state.pop("file_path", None)
        st.session_state.pop("key", None)
        st.session_state.pop("selected_db", None)
        st.rerun()
# Main Application
def show_page():
    st.sidebar.title("SecureByte - Password Manager")
    manage_database_ui()
    if "db_unlocked" in st.session_state and st.session_state["db_unlocked"]:
        manage_entries_ui()
    else:
        access_database_ui()

if __name__ == "__main__":
    show_page()