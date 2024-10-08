import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect("defensive.db")
cursor = conn.cursor()

# Define the username of the user you want to delete
username_to_delete = "David Levi"

# Execute the DELETE query
cursor.execute("DELETE FROM clients WHERE username = ?", (username_to_delete,))

# Commit the changes
conn.commit()

# Verify if the deletion was successful
cursor.execute("SELECT * FROM clients WHERE username = ?", (username_to_delete,))
result = cursor.fetchone()

if result is None:
    print(f"User {username_to_delete} successfully deleted.")
else:
    print(f"Failed to delete user {username_to_delete}.")

# Close the connection
conn.close()
