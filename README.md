# SecureByte Password Manager

## Overview

The SecureByte Password Manager is a secure application designed to manage and store passwords. It uses advanced encryption techniques to ensure the safety of your data. The application is built using Streamlit for the user interface and SQLite for database management. It also includes various algorithms for password strength analysis and similarity checks.

## Features

- **Create, Load, and Delete Databases**: Manage multiple password databases with ease.
- **Add, View, Edit, and Delete Password Entries**: Perform CRUD operations on password entries.
- **Password Encryption**: Encrypt passwords using AES-CBC encryption.
- **Password Strength Analysis**: Analyze password strength using the knapsack algorithm and zxcvbn library.
- **Password Similarity Check**: Compare passwords using the Longest Common Subsequence (LCS) algorithm.

## Project Structure

```
SecureByte Password Manager/
├── password_manager.py
├── password_databases/
│   ├── <database_name>.db
│   ├── <database_name>.db.meta
│   └── passwords.json
├── salt.key
└── README.md
```

## Encryption

### Key Derivation

The key for encryption is derived using the PBKDF2 algorithm with a salt. The salt is either generated or loaded from the

salt.key

 file.

```python
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=32, count=1000000)
```

### AES-CBC Encryption

Passwords are encrypted using AES in CBC mode. The encryption process includes padding the data to match the AES block size.

```python
def encrypt(raw: bytes, key: bytes) -> bytes:
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(raw)
    return iv + cipher.encrypt(padded_data)

def decrypt(enc: bytes, key: bytes) -> bytes:
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[AES.block_size:]))
```

## Algorithms

### Longest Common Subsequence (LCS)

The LCS algorithm is used to compare passwords and determine their similarity.

```python
def lcs(X, Y):
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
```

### Knapsack Algorithm

The knapsack algorithm is used to analyze password strength based on various characteristics.

```python
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

    selected_chars = []
    w = max_weight
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i - 1][w]:
            selected_chars.append(items[i - 1][0])
            w -= items[i - 1][1]

    return selected_chars, dp[n][max_weight]
```

## User Interface

The user interface is built using Streamlit. It includes various functions to manage databases and password entries.

### Manage Databases

```python
def manage_database_ui():
    st.sidebar.title("SecureByte - Manage Password Databases")
    databases, metadata = show_databases()

    st.sidebar.header("Your Databases")
    for db in databases:
        category = metadata.get(db, {}).get('category', 'Uncategorized')
        st.sidebar.write(f"**{db}** ({category})")

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
```

### Manage Entries

```python
def manage_entries_ui():
    file_path = st.session_state["file_path"]
    key = st.session_state["key"]

    conn, _ = load_database(file_path, key)

    st.header(f"Manage Password Entries in '{st.session_state['selected_db']}'")
    option = st.radio("Choose an option", ["Add Entry", "View Entries", "Edit Entry", "Delete Entry", "Check Similarities"])

    if option == "Add Entry":
        st.subheader("Add a New Password Entry")
        with st.form(key='add_entry_form'):
            name = st.text_input("Entry Name (required)", key="add_entry_name")
            with st.expander("Add a Description (optional)"):
                description = st.text_area("Description", key="add_entry_description")
            password = st.text_input("Password (required)", type="password", key="add_entry_password")
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
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error saving entry: {e}")

    elif option == "View Entries":
        st.subheader("View All Password Entries")
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
        cursor = conn.execute("SELECT id, name, description, encrypted_password FROM passwords")
        rows = cursor.fetchall()

        if rows:
            entries = {row[1]: row for row in rows}
            selected_entry = st.selectbox("Select Entry to Edit", list(entries.keys()), key="edit_entry_select")
            entry = entries[selected_entry]

            with st.form(key='edit_entry_form'):
                name = st.text_input("Entry Name (required)", value=entry[1], key="edit_entry_name")
                description = st.text_area("Description", value=entry[2], key="edit_entry_description")
                password = st.text_input("Password (required)", type="password", value=decrypt(base64.b64decode(entry[3]), key).decode('utf-8'), key="edit_entry_password")
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

    save_database(conn)

    if st.button("Close Database", key="close_database_button"):
        st.session_state["db_unlocked"] = False
        st.session_state.pop("file_path", None)
        st.session_state.pop("key", None)
        st.session_state.pop("selected_db", None)
        st.rerun()
```

## Running the Application

To run the application, execute the following command:

```sh
streamlit run password_manager.py
```

## Dependencies

The application requires the following Python packages:

- Streamlit
- SQLite
- PyCryptodome
- Plotly
- zxcvbn

Install the dependencies using the following command:

```sh
pip install streamlit sqlite3 pycryptodome plotly zxcvbn
```

## Future Enhancements

- **Two-Factor Authentication**: Add an extra layer of security by implementing two-factor authentication.
- **Password Generation**: Include a feature to generate strong passwords.
- **Cloud Storage**: Allow users to store their databases in the cloud for easy access across devices.
- **User Management**: Implement user accounts and permissions for shared databases.
- **Backup and Restore**: Provide options to backup and restore databases.License

This project is licensed under the MIT License. See the

LICENSE

 file for details.

Similar code found with 2 license types
