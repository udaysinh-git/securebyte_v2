import streamlit as st
import sqlite3

def knapsack(capacity, weights, values, n):
    K = [[0 for x in range(capacity + 1)] for x in range(n + 1)]
    for i in range(n + 1):
        for w in range(capacity + 1):
            if i == 0 or w == 0:
                K[i][w] = 0
            elif weights[i-1] <= w:
                K[i][w] = max(values[i-1] + K[i-1][w-weights[i-1]], K[i-1][w])
            else:
                K[i][w] = K[i-1][w]
    return K[n][capacity]

def show_page():
    st.title("Optimize Storage")
    capacity = st.number_input("Enter the storage capacity", min_value=1)
    
    # Create a new SQLite connection
    conn = sqlite3.connect('securebyte.db')
    c = conn.cursor()
    
    c.execute("SELECT size, importance FROM encrypted_data")
    data = c.fetchall()
    conn.close()
    
    if data:
        sizes = [row[0] for row in data]
        importances = [row[1] for row in data]
        n = len(sizes)
        max_importance = knapsack(capacity, sizes, importances, n)
        st.write(f"Maximum importance that can be stored: {max_importance}")
    else:
        st.write("No data available to optimize.")