
import base64
import socket
import sys
import threading
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

my_mutex = threading.Lock()


def decode_message(password, salt, message):
    password = bytes(password, "utf-8")
    salt = bytes(salt, "utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.decrypt(message)
    return token


def receive_data(prt, password, salt):
    data = prt.recv(100000)
    msg = decode_message(password, salt, data)
    msg = msg.decode("utf-8")
    # get the current time and print it with the message
    time = datetime.now().time()
    time = time.strftime("%H:%M:%S")
    print(msg + " " + time)



def main():
    global my_mutex
    # get all of the input
    password = sys.argv[1]
    salt = sys.argv[2]
    port = sys.argv[3]
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", int(port)))
    server.listen()
    while True:
        client_socket, client_address = server.accept()
        s = threading.Thread(target=receive_data(client_socket, password, salt))
        s.start()
        client_socket.close()


if __name__ == '__main__':
    main()
