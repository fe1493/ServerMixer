

import socket
import threading
import sys
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

round_counter = 0


def open_file(file_number):
    fileName = 'messages' + file_number + '.txt'
    file = open(fileName, "r")
    return file


def parse_line(line):
    first_step = line.split(" ")
    message = first_step[0]
    path = first_step[1]
    rnd = first_step[2]
    password = first_step[3]
    salt = first_step[4]
    dest_ip = first_step[5]
    dest_port = first_step[6]
    return message, path, rnd, password, salt, dest_ip, dest_port


def encode_message(password, salt, message):
    password = bytes(password, "utf-8")
    message = bytes(message, "utf-8")
    salt = bytes(salt, "utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.encrypt(message)
    return token


def calc_len_of_path(path):
    list_of_paths = []
    first_step = path.split(",")
    for i in range(len(first_step)):
        list_of_paths.append(first_step[i])
    return list_of_paths


def load_key(pk_to_open):
    pk_file = "pk" + pk_to_open + ".pem"
    with open(pk_file, "rb") as f:
        public = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
    return public


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


def send_message(next_ip, next_port, encrypted_message):
    # time.sleep(5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((next_ip, int(next_port)))
        s.sendall(encrypted_message)
        s.close()


def create_new_message(message, path, password, salt, dest_ip, dest_port):
    next_ip = None
    next_port = None
    encrypted_message = None
    encoded_message = encode_message(password, salt, message)
    dest_ip = socket.inet_aton(dest_ip)
    dest_port = int(dest_port).to_bytes(2, 'big')
    list_of_paths = calc_len_of_path(path)
    msg = dest_ip + dest_port + encoded_message
    # build the full message
    for i in reversed(list_of_paths):
        pk_to_open = i
        # load the public key
        public_key = load_key(pk_to_open)
        # load the next ip
        next_ip_and_port = load_ip_and_port(int(pk_to_open))
        next_ip, next_port = split_ip_and_port(next_ip_and_port)
        encrypted_message = public_key.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        next_ip_bytes = socket.inet_aton(next_ip)
        next_port_bytes = int(next_port).to_bytes(2, 'big')
        # build the message
        msg = next_ip_bytes + next_port_bytes + encrypted_message
    send_message(next_ip, next_port, encrypted_message)


if __name__ == '__main__':
    # wait a few seconds to allow the servers to start working
    X_number = sys.argv[1]
    list_of_messages = []
    dict_of_msgs = {"Message": None, "Path": None, "Round": None, "Password": None, "Salt": None, "Dest_IP": None,
                    "Dest_port": None}
    # open the file
    file = open_file(X_number)
    current_round = 0
    for line in file:
        # #parse the file
        message, path, rnd, password, salt, dest_ip, dest_port = parse_line(line)
        dict_of_msgs["Message"] = message
        dict_of_msgs["Path"] = path
        dict_of_msgs["Round"] = int(rnd)
        dict_of_msgs["Password"] = password
        dict_of_msgs["Salt"] = salt
        dict_of_msgs["Dest_IP"] = dest_ip
        dict_of_msgs["Dest_port"] = dest_port
        dict_copy = dict_of_msgs.copy()
        list_of_messages.append(dict_copy)
    # send the messages based on the round
    while len(list_of_messages):
        lines_to_remove = []
        temp = list_of_messages.copy()
        for mesg in temp:
            if mesg["Round"] == current_round:
                message = mesg["Message"]
                path = mesg["Path"]
                password = mesg["Password"]
                salt = mesg["Salt"]
                dest_ip = mesg["Dest_IP"]
                dest_port = mesg["Dest_port"]
                # t = threading.Thread(target=create_new_message(message, path, password, salt, dest_ip, dest_port))
                # t.start()
                create_new_message(message, path, password, salt, dest_ip, dest_port)
                list_of_messages.remove(mesg)
        current_round = current_round + 1
        # wait a minute to send the next set of messages
        if len(list_of_messages):
            time.sleep(60)
