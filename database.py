import sqlite3
import os
import uuid


class Database:
    _instance = None  # To hold the singleton instance

    def __new__(cls, db_name="defensive.db"):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._init_database(db_name)
        return cls._instance

    def _init_database(self, db_name):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()

        # Always attempt to create the table if it doesn't exist
        self._create_clients_table()
        self.create_files_table()

    def _create_clients_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                uuid TEXT NOT NULL,
                public_key TEXT,
                aes_key TEXT,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def create_files_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL,
                fileName TEXT NOT NULL,
                pathName TEXT NOT NULL,
                verified BOOLEAN DEFAULT FALSE
            )
        ''')
        self.conn.commit()

    def register_user(self, username,user_uuid, public_key=None , aes_key=None):
        self.cursor.execute("SELECT * FROM clients WHERE username=?", (username,))
        user = self.cursor.fetchone()

        if user:
            print(f"User {username} already exists and has UUID: {user[2]}")
            return False, None

        # user_uuid = str(uuid.uuid4()).replace("-", "")[:16]
        self.cursor.execute("INSERT INTO clients (username, uuid, public_key, aes_key) VALUES (?, ?, ?, ?)",
                            (username, user_uuid, public_key, aes_key))
        self.conn.commit()
        print(f"User {username} registered with UUID: {user_uuid}")

        return True, user_uuid

    def register_file(self, user_uuid, fileName, pathName):
        # Check if a file with the same fileName already exists for this user
        self.cursor.execute("SELECT COUNT(*) FROM files WHERE uuid = ? AND fileName = ?", (user_uuid, fileName))
        result = self.cursor.fetchone()

        if result[0] == 0:  # If the count is 0, no such file exists
            self.cursor.execute("INSERT INTO files (uuid, fileName, pathName) VALUES (?, ?, ?)",
                                (user_uuid, fileName, pathName))
            self.conn.commit()
            print(f"File {fileName} registered with user UUID: {user_uuid}")
            return True
        else:
            print(f"File {fileName} already exists for user UUID: {user_uuid}, registration skipped.")
            return False

    def get_files(self, user_uuid):
        self.cursor.execute("SELECT * FROM files WHERE uuid=?", (user_uuid,))
        return self.cursor.fetchall()

    def verify_file(self, fileName):
        self.cursor.execute("UPDATE files SET verified=1 WHERE fileName=?", (fileName,))
        self.conn.commit()
        print(f"File {fileName} verified ")

    def get_user(self, username):
        self.cursor.execute("SELECT * FROM clients WHERE username=?", (username,))
        return self.cursor.fetchone()

    def get_user_uuid(self, username):
        self.cursor.execute("SELECT uuid FROM clients WHERE username=?", (username,))
        return self.cursor.fetchone()

    def get_user_public_key(self, username):
        self.cursor.execute("SELECT public_key FROM clients WHERE username=?", (username,))
        return self.cursor.fetchone()

    def get_user_aes_key(self, uuid):
        self.cursor.execute("SELECT aes_key FROM clients WHERE uuid=?", (uuid,))
        return self.cursor.fetchone()

    def set_user_public_key(self, username, public_key):
        self.cursor.execute("UPDATE clients SET public_key=? WHERE username=?", (public_key, username))
        self.conn.commit()

    def set_user_aes_key(self, username, aes_key):
        self.cursor.execute("UPDATE clients SET aes_key=? WHERE username=?", (aes_key, username))
        self.conn.commit()

    def get_user_by_uuid(self, user_uuid):
        self.cursor.execute("SELECT * FROM clients WHERE uuid=?", (user_uuid,))
        return self.cursor.fetchone()

    def update_last_seen(self, user_uuid):
        self.cursor.execute("UPDATE clients SET last_seen=CURRENT_TIMESTAMP WHERE uuid=?", (user_uuid,))
        self.conn.commit()

    def close(self):
        self.conn.close()
