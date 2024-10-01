import os


def read_port(file_name='port.info'):
    try:
        with open(file_name, 'r') as f:
            return int(f.read())
    except FileNotFoundError:
        print(f"File {file_name} not found , using default port 1256")
        return 1256
    except ValueError:
        print(f"Error reading port from file {file_name}, using default port 1256")
        return 1256


def create_port_file(port, file_name='port.info'):
    try:
        with open(file_name, 'w') as f:
            f.write(str(port))
    except Exception as e:
        print(f"Error writing to file {file_name}: {e}")


def create_data_folder(folder_name='data'):
    try:
        os.mkdir(folder_name)
    except FileExistsError:
        print(f"Folder \"{folder_name}\" already exists")
    except Exception as e:
        print(f"Error creating folder \"{folder_name}\": {e}")
