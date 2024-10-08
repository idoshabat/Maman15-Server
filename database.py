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
        self._create_table()

    def _create_table(self):
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

    def register_user(self, username, public_key=None , aes_key=None):
        self.cursor.execute("SELECT * FROM clients WHERE username=?", (username,))
        user = self.cursor.fetchone()

        if user:
            return False, None

        user_uuid = str(uuid.uuid4()).replace("-", "")[:16]
        self.cursor.execute("INSERT INTO clients (username, uuid, public_key, aes_key) VALUES (?, ?, ?, ?)",
                            (username, user_uuid, public_key, aes_key))
        self.conn.commit()

        return True, user_uuid

    def get_user(self, username):
        self.cursor.execute("SELECT * FROM clients WHERE username=?", (username,))
        return self.cursor.fetchone()

    def get_user_uuid(self, username):
        self.cursor.execute("SELECT uuid FROM clients WHERE username=?", (username,))
        return self.cursor.fetchone()

    def get_user_public_key(self, username):
        self.cursor.execute("SELECT public_key FROM clients WHERE username=?", (username,))
        return self.cursor.fetchone()

    def get_user_aes_key(self, username):
        self.cursor.execute("SELECT aes_key FROM clients WHERE username=?", (username,))
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

    def close(self):
        self.conn.close()
