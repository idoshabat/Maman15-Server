import struct
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from database import Database

MAX_FILE_SIZE = 1024 * 1024

REQUEST_HEADER_LENGTH = 23
REQUEST825_LENGTH = REQUEST_HEADER_LENGTH + 255
REQUEST826_LENGTH = REQUEST_HEADER_LENGTH + 255 + 160
REQUEST827_LENGTH = REQUEST_HEADER_LENGTH + 255
REQUEST828_LENGTH = REQUEST_HEADER_LENGTH + 4 + 4 + 255 + MAX_FILE_SIZE
REQUEST900_LENGTH = REQUEST_HEADER_LENGTH + 255
REQUEST901_LENGTH = REQUEST_HEADER_LENGTH + 255
REQUEST902_LENGTH = REQUEST_HEADER_LENGTH + 255

RESPONSE_HEADER_LENGTH = 7
RESPONSE1600_LENGTH = RESPONSE_HEADER_LENGTH + 16
RESPONSE1601_LENGTH = RESPONSE_HEADER_LENGTH
RESPONSE1602_LENGTH = RESPONSE_HEADER_LENGTH + 16  # + AES key !!!!!
RESPONSE1603_LENGTH = RESPONSE_HEADER_LENGTH + 16 + 4 + 255 + 4
RESPONSE1604_LENGTH = RESPONSE_HEADER_LENGTH + 16
RESPONSE1605_LENGTH = RESPONSE_HEADER_LENGTH + 16  # + AES key !!!!!
RESPONSE1606_LENGTH = RESPONSE_HEADER_LENGTH + 16

AES_KEY_LENGTH = 256
RSA_KEY_LENGTH = 1024

UUID_LENGTH = 16


def handle_request(sel, conn):
    data = conn.recv(REQUEST_HEADER_LENGTH)
    print(len(data))
    if not data:
        print('Connection closed')
        sel.unregister(conn)
        conn.close()
        raise Exception("Connection closed")

    try:
        client_id, version, code, payload_size = struct.unpack('<16sBHI', data)
        print(f'Received client_id: {client_id}\n, version: {version}\n, code: {code}\n,payloadsize: {payload_size}\n ')

        payload = b''
        remaining = payload_size
        while remaining > 0:
            chunk = conn.recv(min(4096, remaining))  # Read in chunks (up to 4KB at a time)
            if not chunk:
                print("Client disconnected before sending complete payload")
                return
            payload += chunk
            remaining -= len(chunk)

        print(f"Payload received: {payload}")
        print("Payload size: ", len(payload))

        return client_id, version, code, payload_size, payload
        # payload = data[REQUEST_HEADER_LENGTH:REQUEST_HEADER_LENGTH + payload_size].decode('utf-8')

        # Reply back to the client
        # reply = payload + ' - OK'
        # reply_data = bytearray(reply, 'utf-8')
    except Exception as e:
        print(f"Error handling data: {e}")
        reply = "Invalid data received"
        reply_data = bytearray(reply, 'utf-8')
        sel.unregister(conn)
        conn.close()

    # reply_data = "OK".encode("utf-8")
    # new_data = bytearray(1024)
    # for i in range(min(len(reply_data), len(new_data))):
    #     new_data[i] = reply_data[i]
    #
    # conn.sendall(new_data)


def handle825(conn, client_id, version, code, payload_size, payload):
    print("Handling request 825")
    if len(payload) != REQUEST825_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 825: {len(payload)}")
        return

    # Extract the payload
    # payload = payload.decode('utf-8')
    name = payload.decode('utf-8').rstrip('\x00')
    print(f"Payload for request 825: {name}")

    db = Database()
    user = db.get_user(name)
    if user:
        print("User exists")
        response = bytearray(RESPONSE1601_LENGTH)
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 1, 1601, 0)
        conn.sendall(response)
    else:
        print(f"User {name} not found")
        response = bytearray(RESPONSE1600_LENGTH)
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 1, 1600, UUID_LENGTH)
        generated_uuid = str(uuid.uuid4()).replace("-", "")[:UUID_LENGTH]
        response[RESPONSE_HEADER_LENGTH:] = generated_uuid.encode('utf-8')
        conn.sendall(response)
        db.register_user(name, generated_uuid)



def handle826(conn, client_id, version, code, payload_size, payload):
    print("Handling request 826")
    if len(payload) != REQUEST826_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 826: {len(payload)}")
        return

    # Extract the payload
    # payload = payload.decode('utf-8')
    name = payload[:255].decode('utf-8').rstrip('\x00')
    pubKey = payload[255:]
    # print(f"Payload for request 826:\nname: {name}")

    try:
        # Load the RSA public key
        public_key = RSA.import_key(pubKey)
        cipher_rsa = PKCS1_OAEP.new(public_key)

        # Generate a random AES key
        aes_key = get_random_bytes(32)  # 256-bit AES key
        # print("Length of AES key ", len(aes_key))
        # print("AES key: ", aes_key)

        # Encrypt the AES key using the RSA public key
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        # print("Length of encrypted key ", len(encrypted_aes_key))

        db = Database()
        db.set_user_public_key(name, pubKey)
        db.set_user_aes_key(name, aes_key)
        # db.close()

        # f = open(f"{name}.txt", "a")
        # f.write(f"\n{aes_key}")
        # f.close()

        # Send the encrypted AES key back to the client
        response = bytearray(RESPONSE_HEADER_LENGTH + RESPONSE1602_LENGTH + len(encrypted_aes_key))
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 1, 1602, len(encrypted_aes_key))
        response[RESPONSE_HEADER_LENGTH:RESPONSE_HEADER_LENGTH + 16] = struct.pack('<16s', client_id)
        response[RESPONSE_HEADER_LENGTH + 16:] = struct.pack(f'<{len(encrypted_aes_key)}s', encrypted_aes_key)
        conn.sendall(response)

    except Exception as e:
        print(f"Error handling request 826: {e}")

def handle827(conn, client_id, version, code, payload_size, payload):
    print("Handling request 827")
    if len(payload) != REQUEST827_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 827: {len(payload)}")
        return

    # Extract the payload
    # payload = payload.decode('utf-8')
    name = payload.decode('utf-8').rstrip('\x00')
    print(f"Payload for request 827: {name}")

    db = Database()
    user = db.get_user(name)
    if user:
        print("User exists")
        response = bytearray(RESPONSE1600_LENGTH)
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 3, 1600, UUID_LENGTH)
        response[RESPONSE_HEADER_LENGTH:] = user[2].encode('utf-8')
        conn.sendall(response)
    else:
        print(f"User {name} not found")
        response = bytearray(RESPONSE1601_LENGTH)
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 3, 1601, 0)
        conn.sendall(response)

def handle828(conn, client_id, version, code, payload_size, payload):
    print("Handling request 828")
    lengthTillFileContent = 4+4+2+2+255
    contentSize , originalFileSize , packetNumber , totalPackets , fileName= struct.unpack('<IIHH255s', payload[:lengthTillFileContent])
    fileName = fileName.decode('utf-8').rstrip('\x00')
    content = payload[lengthTillFileContent:]
    print(f"Content: {content}")

    db = Database()
    user = db.get_user_by_uuid(client_id)
    aes_key = db.get_user_aes_key(client_id.decode('utf-8'))
    print(f"UUID: {client_id.decode('utf-8')}")
    print(f"Version: {version}")
    print(f"Code: {code}")
    print(f"Payload size: {payload_size}")
    print(f"User: {user}")
    print(f"AES key: {aes_key}")
    # #decrypt the content
    # cipher_aes = AES.new(aes_key[0], AES.MODE_CBC, content[:16])
    # decrypted_content = cipher_aes.decrypt(content[16:])
    # print(f"Decrypted content: {decrypted_content}")
