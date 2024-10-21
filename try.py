import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect("defensive.db")
cursor = conn.cursor()

# Execute the DELETE query
cursor.execute("DELETE FROM clients")

# Commit the changes
conn.commit()

# Verify if the deletion was successful
cursor.execute("SELECT * FROM clients")
result = cursor.fetchone()

if result is None:
    print(f"All users have been deleted successfully.")
else:
    print("Error deleting")

#delete all files
cursor.execute("DELETE FROM files")
conn.commit()

cursor.execute("SELECT * FROM files")
result = cursor.fetchone()

if result is None:
    print(f"All files have been deleted successfully.")
else:
    print("Error deleting")

# Close the connection
conn.close()
