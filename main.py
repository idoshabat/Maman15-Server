from server import start_server
from database import Database

if __name__ == '__main__':
    db = Database()
    start_server()
    db.close()
