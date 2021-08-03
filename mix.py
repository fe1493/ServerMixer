
import sys
import socket
import threading
import time
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

my_mutex = threading.Lock()
messages = []


def open_file(file_number):
    file_name = 'sk' + file_number + '.pem'
    file = open(file_name, "r")
    return file


def load_key(sk_to_open):
    sk_file = "sk" + sk_to_open + ".pem"
    with open(sk_file, "rb") as f:
        private = serialization.load_pem_private_key(
            f.read(), None, backend=default_backend()
        )
    return private


def load_ip_and_port(counter):
    fileName = "ips.txt"
    with open(fileName) as fp:
        for i, line in enumerate(fp):
            if i == counter - 1:
                ip = line
                break
    return ip


def split_ip_and_port(next_ip_and_port):
    first_step = next_ip_and_port.split(" ")
    ip = first_step[0]
    port = first_step[1]
    return ip, port


def decrypt_msg(private_key, rest_of_data):
    plaintext = private_key.decrypt(
        rest_of_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def send_message():
    while True:
        # time.sleep(60)
        temp_arr = messages.copy()
        random.shuffle(temp_arr)
        messages.clear()
        for msg in temp_arr:
            rest_of_data = msg[0]
            next_ip = msg[1]
            next_port = msg[2]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((next_ip, next_port))
                s.sendall(rest_of_data)
                s.close()
        time.sleep(60)
    # threading.Timer(60.0, send_message).start()


if __name__ == '__main__':
    # main()
    Y_number = sys.argv[1]
    # load the private key
    private_key = load_key(Y_number)
    ip_and_port = load_ip_and_port(int(Y_number))
    ip, port = split_ip_and_port(ip_and_port)
    t = threading.Thread(target=send_message)
    t.daemon = True
    t.start()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", int(port)))
    server.listen()

    while True:
        client_socket, client_address = server.accept()

        data = client_socket.recv(10000)
        # check if we actually received data
        if not data:
            break
        decrypted_msg = decrypt_msg(private_key, data)
        # extract next ip and next port
        next_ip = socket.inet_ntoa(decrypted_msg[:4])
        next_port = int.from_bytes(decrypted_msg[4:6], 'big')
        rest_of_data = decrypted_msg[6:]
        full_block = [rest_of_data, next_ip, next_port]
        # collect the data
        messages.append(full_block)
        # # make a new thread for each message
        client_socket.close()

