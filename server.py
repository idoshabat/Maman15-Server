import socket
import struct
import selectors
from handle_files import read_port, create_port_file, create_data_folder
from handle_request import handle_request, handle825, handle826, handle827, handle828, handle900, handle901, handle902
from database import Database

SIGNUP_CODE = 825
RSA_KEY_TRANSFER_CODE = 826
RECONNECT_CODE = 827
FILE_TRANSFER_CODE = 828
VALID_CRC = 900
TRANSFER_ERROR = 901
FILE_TRANSFER_ABORT = 902

sel = selectors.DefaultSelector()
create_port_file()
PORT = read_port()
create_data_folder()
HOST = '127.0.0.1'


def accept_connection(sock, mask):
    conn, addr = sock.accept()
    # print('Connected by', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, handle_connection)


def handle_connection(conn, mask):
    # print("conn: ", conn)
    # print("mask: ", mask)
    try:
        client_id, version, code, payload_size, payload = handle_request(sel, conn)
        if code == SIGNUP_CODE:  # 825
            handle825(conn, client_id, version, code, payload_size, payload)
        elif code == RSA_KEY_TRANSFER_CODE:  # 826
            handle826(conn, client_id, version, code, payload_size, payload)
        elif code == RECONNECT_CODE:  # 827
            handle827(conn, client_id, version, code, payload_size, payload)
        elif code == FILE_TRANSFER_CODE:  # 828
            handle828(conn, client_id, version, code, payload_size, payload)
        elif code == VALID_CRC:  # 900
            handle900(conn, client_id, version, code, payload_size, payload)
        elif code == TRANSFER_ERROR:  # 901
            handle901(conn, client_id, version, code, payload_size, payload)
        elif code == FILE_TRANSFER_ABORT:  # 902
            handle902(conn, client_id, version, code, payload_size, payload)
        else:
            print(f"Invalid request code: {code}")
    except ConnectionResetError:
        print("Client connection reset by peer")
    except Exception as e:
        print(f"Error handling request: {e}")
    finally:
        try:
            sel.unregister(conn)
        except Exception as e:
            print(f"Error unregistering connection: {e}")
        conn.close()
        print("Connection closed")


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, accept_connection)
        print(f"Server listening on {HOST}:{PORT}")

        try:
            while True:
                events = sel.select(timeout=None)  # Wait for events
                for key, mask in events:
                    callback = key.data  # Retrieve the callback function (either accept_connection or handle_client)
                    callback(key.fileobj, mask)  # Call the function with the corresponding socket
        except KeyboardInterrupt:
            print("Server shutting down")
        finally:
            sel.close()
            s.close()

# if __name__ == "__main__":
#     start_server()
