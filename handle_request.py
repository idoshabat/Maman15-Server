import os
import random
import struct
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from database import Database
from cksum import read_string, read_file

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
        # Read the payload
        payload = struct.unpack(f'<{payload_size}s', conn.recv(payload_size))[0]
        return client_id, version, code, payload_size, payload

    except Exception as e:
        print(f"Error handling data: {e}")
        # response with code 1607
        response = bytearray(RESPONSE_HEADER_LENGTH)
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 3, 1607, 0)
        conn.sendall(response)
        sel.unregister(conn)
        conn.close()


def handle825(conn, client_id, version, code, payload_size, payload):
    print("Handling request 825")
    if len(payload) != REQUEST825_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 825: {len(payload)}")
        return

    # Extract the payload
    name = payload.decode('utf-8').rstrip('\x00')

    db = Database()  # Create a new database connection
    user = db.get_user(name)  # Check if the user already exists
    if user:  # If the user exists
        print("User exists")
        # Send response 1601
        response = bytearray(RESPONSE1601_LENGTH)
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 1, 1601, 0)
        conn.sendall(response)
    else:  # If the user does not exist
        print(f"User {name} not found")
        # create a new folder for the user in the data folder
        os.makedirs(f"data/{name}", exist_ok=True)
        # Send response 1600
        response = bytearray(RESPONSE1600_LENGTH)
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 1, 1600, UUID_LENGTH)  # Header + UUID
        generated_uuid = str(uuid.uuid4()).replace("-", "")[:UUID_LENGTH]  # Generate a new UUID (16 bytes)
        response[RESPONSE_HEADER_LENGTH:] = generated_uuid.encode('utf-8')  # 16 bytes for UUID
        conn.sendall(response)
        db.register_user(name, generated_uuid)  # Register the user in the database


def handle826(conn, client_id, version, code, payload_size, payload):
    print("Handling request 826")
    if len(payload) != REQUEST826_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 826: {len(payload)}")
        return

    # Extract the payload
    name = payload[:255].decode('utf-8').rstrip('\x00')
    pubKey = payload[255:]

    try:
        # Load the RSA public key
        public_key = RSA.import_key(pubKey)
        cipher_rsa = PKCS1_OAEP.new(public_key)

        # Generate a random AES key
        aes_key = get_random_bytes(32)  # 256-bit AES key

        # Encrypt the AES key using the RSA public key
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        db = Database()  # Create a new database connection
        db.set_user_public_key(name, pubKey)  # Save the public key in the database
        db.set_user_aes_key(name, aes_key)  # Save the AES key in the database

        # Send the encrypted AES key back to the client
        response = bytearray(
            RESPONSE_HEADER_LENGTH + RESPONSE1602_LENGTH + len(encrypted_aes_key))  # Header + UUID + AES key
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 1, 1602, len(encrypted_aes_key) + UUID_LENGTH)  # Header
        response[RESPONSE_HEADER_LENGTH:RESPONSE_HEADER_LENGTH + 16] = struct.pack('<16s', client_id)  # UUID
        response[RESPONSE_HEADER_LENGTH + 16:] = struct.pack(f'<{len(encrypted_aes_key)}s',
                                                             encrypted_aes_key)  # AES key
        conn.sendall(response)  # Send the response to the client

    except Exception as e:
        print(f"Error handling request 826: {e}")


def handle827(conn, client_id, version, code, payload_size, payload):
    print("Handling request 827")
    if len(payload) != REQUEST827_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 827: {len(payload)}")
        return

    # Extract the payload
    name = payload.decode('utf-8').rstrip('\x00')

    db = Database()  # Create a new database connection
    user = db.get_user(name)  # Check if the user already exists
    if user:  # If the user exists
        print("User exists")
        username = user[1]  # Get the username
        public_key = RSA.import_key(db.get_user_public_key(username)[0])  # Load the RSA public key
        cipher_rsa = PKCS1_OAEP.new(public_key)  # Create a new RSA cipher

        aes_key = db.get_user_aes_key(client_id.decode('utf-8'))[0]  # Load the AES key
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)  # Encrypt the AES key
        response = bytearray(RESPONSE1605_LENGTH + len(encrypted_aes_key))  # Create the response
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 3, 1605, UUID_LENGTH + len(encrypted_aes_key))  # Header
        response[RESPONSE_HEADER_LENGTH:RESPONSE_HEADER_LENGTH + UUID_LENGTH] = user[2].encode('utf-8')  # UUID
        response[RESPONSE_HEADER_LENGTH + UUID_LENGTH:] = struct.pack(f'<{len(encrypted_aes_key)}s',
                                                                      encrypted_aes_key)  # AES key
        conn.sendall(response)  # Send the response to the client
    else:  # If the user does not exist
        print(f"User {name} not found")
        response = bytearray(RESPONSE1606_LENGTH)  # Create the response
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 3, 1606, UUID_LENGTH)  # Header
        response[RESPONSE_HEADER_LENGTH:] = client_id  # UUID
        conn.sendall(response)  # Send the response to the client


def handle828(conn, client_id, version, code, payload_size, payload):
    print("Handling request 828")
    random_zero_or_one = random.randint(0, 1)  # Randomly choose 0 or 1 (used for checksum)
    lengthTillFileContent = 4 + 4 + 2 + 2 + 255
    contentSize, originalFileSize, packetNumber, totalPackets, fileName = struct.unpack('<IIHH255s',
                                                                                        payload[
                                                                                        :lengthTillFileContent])  # Extract the payload
    fileName = fileName.decode('utf-8').rstrip('\x00')  # Decode the file name
    content = payload[lengthTillFileContent:]  # Extract the content

    db = Database()  # Create a new database connection
    user = db.get_user_by_uuid(client_id.decode('utf-8'))  # Get the user by UUID
    aes_key = db.get_user_aes_key(client_id.decode('utf-8'))  # Get the AES key
    username = user[1]  # Get the username

    # Decrypt the content using AES CBC with IV full of zeros
    iv = b'\x00' * 16  # IV is 16 bytes of zeros
    cipher_aes = AES.new(aes_key[0], AES.MODE_CBC, iv)  # Create a new AES cipher
    decrypted_content_padded = cipher_aes.decrypt(content)  # Decrypt the content

    # Remove padding (PKCS7)
    decrypted_content = remove_padding(decrypted_content_padded)

    # Write the decrypted content to a file
    file_path = f"data/{username}/{fileName}"
    print(f"Writing {len(decrypted_content)} bytes to {file_path}")

    if not os.path.exists(file_path):  # File does not exist
        if packetNumber == 1:  # If this is the first packet , create the file
            with open(file_path, 'wb') as f:
                f.write(decrypted_content)
                print(f"File {fileName} created")
    else:  # File already exists
        if packetNumber == 1:  # If this is the first packet, overwrite the existing file
            os.remove(file_path)
            with open(file_path, 'wb') as f:
                f.write(decrypted_content)
                print(f"File {fileName} overwritten")
        else:  # If this is not the first packet, append to the existing file
            with open(file_path, 'ab') as f:
                f.write(decrypted_content)
                print(f"File {fileName} appended")

    if packetNumber == totalPackets:
        # Compute checksum of the written file
        cksum_str = read_file(file_path)
        cksum = int(cksum_str.split('\t')[0]) + random_zero_or_one

        # save the file in the database
        db.register_file(client_id.decode('utf-8'), fileName, file_path)

        # Send the checksum back to the client
        response = bytearray(RESPONSE_HEADER_LENGTH + RESPONSE1603_LENGTH)
        response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 3, 1603, RESPONSE1603_LENGTH - RESPONSE_HEADER_LENGTH)
        response[RESPONSE_HEADER_LENGTH:RESPONSE_HEADER_LENGTH + 16] = struct.pack('<16s', client_id)
        response[RESPONSE_HEADER_LENGTH + 16:RESPONSE_HEADER_LENGTH + 20] = struct.pack('<I', originalFileSize)
        response[RESPONSE_HEADER_LENGTH + 20:RESPONSE_HEADER_LENGTH + 20 + 255] = struct.pack('<255s',
                                                                                              fileName.encode('utf-8'))
        response[RESPONSE_HEADER_LENGTH + 20 + 255:] = struct.pack('<I', cksum)
        conn.sendall(response)


def handle900(conn, client_id, version, code, payload_size, payload):
    print("Handling request 900")
    if len(payload) != REQUEST900_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 900: {len(payload)}")
        return

    # Extract the payload
    fileName = payload.decode('utf-8').strip('\x00')

    # verify file
    db = Database()
    db.verify_file(fileName)

    # response with code 1604
    response = bytearray(RESPONSE_HEADER_LENGTH + RESPONSE1604_LENGTH)
    response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 3, 1604, UUID_LENGTH)
    response[RESPONSE_HEADER_LENGTH:] = client_id
    conn.sendall(response)


def handle901(conn, client_id, version, code, payload_size, payload):
    print("Handling request 901")
    if len(payload) != REQUEST901_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 901: {len(payload)}")
        return

    # Extract the payload
    fileName = payload.decode('utf-8').strip('\x00')
    print(f"File {fileName} has not been registered")


def handle902(conn, client_id, version, code, payload_size, payload):
    print("Handling request 902")
    if len(payload) != REQUEST902_LENGTH - REQUEST_HEADER_LENGTH:
        print(f"Invalid payload length for request 902: {len(payload)}")
        return

    # Extract the payload
    fileName = payload.decode('utf-8').strip('\x00')
    print(f"File {fileName} has an error 3 times and will be aborted")

    #extract the username
    db = Database()
    user = db.get_user_by_uuid(client_id.decode('utf-8'))
    username = user[1]

    # delete the file
    os.remove(f'data/{username}/{fileName}')

    # response with code 1604
    response = bytearray(RESPONSE_HEADER_LENGTH + RESPONSE1604_LENGTH)
    response[:RESPONSE_HEADER_LENGTH] = struct.pack('<BHI', 3, 1604, UUID_LENGTH)
    response[RESPONSE_HEADER_LENGTH:] = client_id
    conn.sendall(response)


def remove_padding(data):
    """Remove PKCS7 padding from the decrypted data."""
    padding_length = data[-1]  # Last byte tells how much padding was added
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding length detected.")
    return data[:-padding_length]
