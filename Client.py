import socket
import threading
import sys
import ast
import getpass
import time
import signal
import os
import platform
import subprocess
import random
import Encryption
import codecs
import sqlite3
from Colors import bcolors
import pickle
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


# Global variables

HOST = '127.0.0.1'
username = ""
password = ""
MAX_SIZE = 65536


FORMAT = 'latin-1'

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# Chat variables
sender_chats = {}
receiver_chats = {}
in_chat_with = None

# Encryption keys
publickey = None
privatekey = None
server_pkey = None
LTK = None


b = None
arya = 'ANN'


def send(resp):
    sock.sendall(resp.encode())

def save_message_to_database(sender, receiver, message, timestamp, signature=""):
    global username, password

    # encrypt message using hash of the password
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())

    key = Encryption.cipher_from_hash(digest)

    enc_sender = Encryption.sym_encrypt(sender, key)
    enc_receiver = Encryption.sym_encrypt(receiver, key)
    enc_message = Encryption.sym_encrypt(message, key)
    enc_signature = Encryption.sym_encrypt(signature, key)
    enc_timestamp = Encryption.sym_encrypt(str(timestamp), key)

    # add message to database
    conn, curs = connect_to_database()
    curs.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?)", (username, enc_sender, enc_receiver, enc_message, enc_signature, enc_timestamp))
    conn.commit()
    conn.close()

def raw_initialization():
    global sender_chats, receiver_chats, in_chat_with, username, password, publickey, privatekey, server_pkey, LTK
    # Chat variables
    sender_chats = {}
    receiver_chats = {}
    in_chat_with = None

    # Encryption keys
    publickey = None
    privatekey = None
    username = None
    password = None

    print("Variables are raw initialized!")


def save_keys(uname, publickey, privatekey, password):
    global b, arya
    try:
        with open(f"keys\{uname}_public.pem", "wb") as f:
            f.write(publickey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())

        key = Encryption.cipher_from_hash(digest)

        private_bytes = privatekey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
        private_bytes = Encryption.sym_encrypt(private_bytes.decode(FORMAT), key).encode(FORMAT)


        with open(f"keys\{uname}_private.pem", "wb") as f:
            f.write(private_bytes)
        print("Keys are saved successfully!")
    except Exception as e:
        print(e)

def load_keys(uname):
    global arya
    try:
        with open(f"keys\{uname}_public.pem", "rb") as f:
            publickey = serialization.load_pem_public_key(
                f.read()
            )
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())

        key = Encryption.cipher_from_hash(digest)

        with open(f"keys\{uname}_private.pem", "rb") as f:

            privatekey = serialization.load_pem_private_key(
                Encryption.sym_decrypt(f.read().decode(FORMAT), key).encode(FORMAT),
                password = None
            )

        print("Keys are loaded successfully!")
        return publickey, privatekey
    except Exception as e:
        print("Error in loading keys!")
        print(e)
    

def connect_to_database():
    global conn, curs
    if(os.path.exists("users.db")):
        conn = sqlite3.connect("users.db")
        curs = conn.cursor()
        return conn, curs
    else:
        print("Error: Database not found")


def register():
    global username, commands, publickey, privatekey
    while True:
        uname = input(bcolors.OKBLUE+"Choose a username : "+bcolors.ENDC)
        passwd = getpass.getpass(bcolors.OKBLUE+"Enter Password : "+bcolors.ENDC)
        retype_passwd = getpass.getpass(bcolors.OKBLUE+"Re-type Password : "+bcolors.ENDC)

        if(passwd==retype_passwd):
            break
        else:
            print(bcolors.FAIL+"Passwords do not match, try again."+bcolors.ENDC)

    publickey, privatekey = Encryption.genkeys(512 * 8)

    nonce = random.randint(100000, 999999)

    try:
        data_to_send = {
            "type": "register",
            "plain": {
            "username": uname,
            "password": passwd,
            "pbkey": Encryption.serialize_public_key(publickey),
            },
            "nonce": nonce
        }

        send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))


        response = Encryption.sym_decrypt(sock.recv(MAX_SIZE).decode(), LTK)
        response = json.loads(response)

        check, data = Encryption.check_sign(response, server_pkey)
        
        if check != 0 or data['status'] == "FAIL" or data['nonce'] != nonce + 1:
            print(bcolors.FAIL+"Could not register. Please try again."+bcolors.ENDC)
            return -1

        clear_screen()
        print(bcolors.OKGREEN + f"Successfuly registerd as {uname}" + bcolors.ENDC)
        save_keys(uname, publickey, privatekey, passwd)
        return 0

    except Exception as e:
        print(e)
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0
    

def login():
    global commands, username, password, privatekey, publickey

    uname = input(bcolors.OKBLUE+"Choose a username : "+bcolors.ENDC)
    passwd = getpass.getpass(bcolors.OKBLUE+"Enter Password : "+bcolors.ENDC)

    try:

        data_to_send = {
            "type": "login",
            "plain": {
            "username": uname,
            "password": passwd,
            },
            "nonce": "Nonce",
            "side_port": int(sys.argv[1])
        }

        send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))
        '''
        response = {
        cipher: "cipher",
        signature: "signature",
        }
        '''
        response = json.loads(sock.recv(MAX_SIZE).decode())
        if response["status"] == "FAIL":
            print(bcolors.FAIL+"Could not login. Please try again."+bcolors.ENDC)
            return -1
        plain = Encryption.sym_decrypt(response["cipher"], LTK)

        signature = response["signature"]

        if Encryption.check_authenticity(plain, signature=signature, public_key=server_pkey) == 0 and \
        json.loads(plain)['nonce'] == "Nonce":
            
            clear_screen()
            print(bcolors.OKGREEN + f"Successfuly logged in as {uname}" + bcolors.ENDC)
            raw_initialization()
            username = uname
            password = passwd
            commands = account_page.copy()
            publickey, privatekey = load_keys(uname)
            return 0
        else:
            print(bcolors.FAIL+"Could not login. Please try again."+bcolors.ENDC)
            return -1
    except Exception as e:
        print(e)
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0


def show_online():
    global server_pkey, privatekey
    nonce = random.randint(100000, 999999)
    data_to_send = {
        "type": "show_online",
        "nonce": nonce,
        "user": username
    }
    data_to_send = Encryption.sign(data_to_send, privatekey)
    send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))
    response = json.loads(sock.recv(MAX_SIZE).decode())
    plain = Encryption.sym_decrypt(response["cipher"], LTK)
    plain = json.loads(plain)
    signature = response["signature"]
    if plain["status"]=="SUCC" and plain['nonce'] == nonce + 1:
        # clear_screen()
        print(bcolors.OKGREEN + f"Online users : {', '.join(plain['online_users'])}" + bcolors.ENDC)
        return 0
    else:
        print(bcolors.FAIL+"Could not get online users. Please try again."+bcolors.ENDC)
        return -1
    
def logout():
    global server_pkey, commands
    nonce = random.randint(100000, 999999)
    data_to_send = {
        "type": "logout",
        "nonce": nonce,
        "user": username
    }
    data_to_send = Encryption.sign(data_to_send, privatekey)
    send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))
    response = json.loads(sock.recv(MAX_SIZE).decode())
    plain = Encryption.sym_decrypt(response["cipher"], LTK)
    plain = json.loads(plain)
    signature = response["signature"]
    if plain["status"]=="SUCC" and plain['nonce'] == nonce + 1:
        clear_screen()
        print(bcolors.OKGREEN + f"Successfuly logged out." + bcolors.ENDC)
        commands = main_page.copy()
        raw_initialization()
        return 0
    else:
        print(bcolors.FAIL+"Could not logout. Please try again."+bcolors.ENDC)
        return -1
    
    # close database connection
    


main_page = {":login" : "Login to an existing account", ":register" : "Create an account"}
main_page_func = {":login" : login, ":register" : register}
account_page = {":chat" : "Chat with an online user",":showonline" : "Show online users",
                 ":logout" : "Logout from the account", ":change_keys" : "Change public and private keys"}



commands = main_page.copy()

def clear_screen():
    # print("-----------------------------------------------------------------------------------")
    os.system('cls' if os.name == 'nt' else 'clear')

# Initial authentication of the server.
def handshake():

    global server_pkey, LTK

    try: 
        key = os.urandom(32)
        iv = os.urandom(16)
        LTK = Encryption.gen_sym_key(key, iv)
        data_to_send = {
            "type": "handshake",
            "nonce" : "nonce",
            "LTK": [key.decode(FORMAT), iv.decode(FORMAT)]
        }
        send(Encryption.asymmetric_encrypt(json.dumps(data_to_send), fname=None, publickey=server_pkey))
        response = json.loads(sock.recv(MAX_SIZE).decode())
        plain = json.loads(response['cipher'])
        signature = response["signature"]
        if Encryption.check_authenticity(response['cipher'], signature,server_pkey) == 0 and \
        plain['status'] == 'SUCC' and plain['nonce'] == 'nonce':
            return 1
        else:
            return 0

    except Exception as e:
        print(e)
        return 0


def initial_client():
    global username
    print(bcolors.OKBLUE+"Trying to connect and handshake with the server..."+bcolors.ENDC)
    
    try:
        sock.connect(('127.0.0.1',17000))
        # hard code babyyyy
        server_sock.bind(('127.0.0.1',int(sys.argv[1])))
        server_sock.listen(10)
        handshake_status = handshake()
        if(handshake_status==1):
            clear_screen()
            print(bcolors.OKGREEN + "Connected to messenger server succesfully :)" + bcolors.ENDC)
        elif(handshake_status==0):
            print(bcolors.FAIL+"Couldn't connect to messenger server!"+ bcolors.ENDC)
            sys.exit(1)  
    except Exception as e:
        print(bcolors.FAIL+"Couldn't connect to messenger server!"+ bcolors.ENDC)
        print(e)
        sys.exit(1)


def load_chat(peer):
    global username, password
    clear_screen()
    terminal_width = 100
    print(bcolors.OKGREEN + f"{username}💬" + bcolors.ENDC, "<===================>", end=' ')
    print(bcolors.OKBLUE+f"🗨️{peer}"+bcolors.ENDC)

    print((terminal_width + 1) * "-")

    if peer in receiver_chats and peer in sender_chats:
        print(receiver_chats[peer]['emojis'])
        print(sender_chats[peer]['emojis'])
        print((terminal_width + 1) * '-')

    
    conn, curs = connect_to_database()
    curs.execute("SELECT * FROM Messages where owner = '%s'"%(username))

    # encrypt message using hash of the password
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    key = Encryption.cipher_from_hash(digest)

    chat_messages = []
    items = curs.fetchall()
    for item in items:
        owner, sender, receiver, message, signature, timestamp = item
        sender = Encryption.sym_decrypt(sender, key)
        receiver = Encryption.sym_decrypt(receiver, key)
        if sender == peer or receiver == peer:
            message = Encryption.sym_decrypt(message, key)
            signature = Encryption.sym_decrypt(signature, key)
            timestamp = Encryption.sym_decrypt(timestamp, key)
        
            chat_messages.append({
                "sender": sender,
                "receiver": receiver,
                "message": message,
                "signature": signature,
                "timestamp": timestamp
            })

    # sort based on timestamp
    chat_messages.sort(key=lambda x: x["timestamp"])

    for message in chat_messages:
        # color sender based on the username
        if message["sender"] == username:
            sender_color = bcolors.OKGREEN
            print(sender_color + f"{message['sender']}💬" + bcolors.ENDC)
            print(sender_color + f" {message['message']}" + bcolors.ENDC)
        else:
            sender_color = bcolors.OKBLUE
            print(f"")
            padding = " " * (terminal_width - len(message['sender']) - 1) + "🗨️"
            print(sender_color + f"{padding + message['sender']}")
            padding = " " * (terminal_width - len(message['message']))
            print(sender_color + f"{padding + message['message']}") 

        # print(sender_color + f"{message['sender']}: {message['message']}" + bcolors.ENDC)

    

def send_message(peer):
    global username, server_pke, in_chat_with
    
    in_chat_with = peer

    while True:
        try:
            load_chat(peer)
            msg = input()
            if msg == ":back":
                in_chat_with = None
                break
            else:
                nonce = random.randint(100000, 999999)

                data_to_peer = {
                    "type": "send_message",
                    "nonce": nonce,
                    "from": username,
                    "to": peer,
                    "message": msg,
                    "new_public_df_key": sender_chats[peer]["public_df_key"]
                }
                data_to_peer = Encryption.sign(data_to_peer, privatekey)
                encrypted_data_to_peer = Encryption.sym_encrypt(json.dumps(data_to_peer), sender_chats[peer]["shared_key"])

                data_to_send = {
                    "type": "send_message",
                    "nonce": nonce,
                    "from": username,
                    "to": peer,
                    "cipher": encrypted_data_to_peer
                }
                data_to_send = Encryption.sign(data_to_send, privatekey)
                encrypted_data_to_send = Encryption.sym_encrypt(json.dumps(data_to_send), LTK)

                send(encrypted_data_to_send)

                # get ack from server
                sock.settimeout(5.0)
                response = sock.recv(MAX_SIZE).decode()
                sock.settimeout(None)
                server_response = json.loads(Encryption.sym_decrypt(response, LTK))
                check, server_response = Encryption.check_sign(server_response, server_pkey)
                if check != 0:
                    print("Server message is not signed correctly!")
                    return -1
                if server_response["status"] == "SUCC":
                    peer_response = Encryption.sym_decrypt(server_response["cipher"], sender_chats[peer]['shared_key'])
                    peer_response = json.loads(peer_response)
                    peer_public_key = sender_chats[peer]["peer_pbkey"]
                    check, peer_response, signature = Encryption.check_sign(peer_response, peer_public_key, True)
                    if check != 0:
                        print(bcolors.FAIL+"Message from peer is not signed correctly! Maybe he has changed his keys."+bcolors.ENDC)
                        del sender_chats[peer]
                        time.sleep(1)
                        return -1
                    if peer_response["nonce"] == nonce or peer_response["from"] == peer:
                        timestamp = int(time.time())
                        save_message_to_database(username, peer, msg, timestamp, signature)
                                        
                        peer_public_df_key = peer_response["public_df_key"]
                        peer_public_df_key = serialization.load_der_public_key(peer_public_df_key.encode(FORMAT))
                        private_df_key = sender_chats[peer]["private_df_key"]
                        parameters = sender_chats[peer]["parameters"]
                        next_cipher, next_public_df_key, next_private_df_key = Encryption.get_next_DH_key(parameters, peer_public_df_key, private_df_key)

                        sender_chats[peer]["shared_key"] = next_cipher
                        sender_chats[peer]["public_df_key"] = next_public_df_key
                        sender_chats[peer]["private_df_key"] = next_private_df_key
                elif server_response["status"] == "NOT_SUCH_ONLINE_USER":
                    print(bcolors.FAIL + f"{peer} is not online!" + bcolors.ENDC)
                    sender_chats.pop(peer)
                    in_chat_with = None
                    time.sleep(1)
                    break
        except Exception:
            sock.settimeout(None)
            print(bcolors.FAIL + f"{peer} is not avaiable!" + bcolors.ENDC)
            sender_chats.pop(peer)
            in_chat_with = None
            time.sleep(1)
            break

    return 0


def initiate_chat():
    global server_pkey, username
    nonce = random.randint(100000, 999999)
    peer = input("Enter the username of the user you want to chat with : ")
    if peer in sender_chats:
        load_chat(peer)
        send_message(peer)
    else:
        data_to_send = {
            "type": "initiate_chat",
            "nonce": nonce,
            "from": username,
            "peer": peer 
        }
        data_to_send = Encryption.sign(data_to_send, privatekey)
        send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))

        # get response from server
        response = json.loads(sock.recv(MAX_SIZE).decode())
        server_response = Encryption.sym_decrypt(response, LTK)
        server_response = json.loads(server_response)

        check, server_response = Encryption.check_sign(server_response, server_pkey)
        if check != 0:
            print(bcolors.FAIL+"Server message is not signed correctly!"+bcolors.ENDC)
            return -1
        if server_response["status"]=="SUCC" and server_response['nonce'] == nonce + 1:
            peer_pbkey = server_response["peer_pbkey"]
            # peer-public public diffey private diffey diffey ghabli
            parameters, public_df_key, private_df_key = Encryption.diffie_first_step()

            p = parameters.parameter_numbers().p
            g = parameters.parameter_numbers().g
            peer_pbkey = Encryption.deserialize_public_key(peer_pbkey)
            sender_chats[peer] = {
                "peer_pbkey": peer_pbkey,
                "private_df_key": private_df_key,
                "public_df_key": public_df_key,
                "shared_key": None,
                "parameters": parameters
            }

            public_df_key = public_df_key.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(FORMAT)

            response = {
                "type": "Exchange",
                "parameters": [p, g],
                "public_df_key": public_df_key,
                "from": username,
                "to": peer,
                "nonce": nonce
            }
            response = Encryption.sign(response, privatekey)

            key = os.urandom(32)
            iv = os.urandom(16)
            shared_key_1 = Encryption.gen_sym_key(key, iv)
            key_cipher = {'key': key.decode(FORMAT), 'iv': iv.decode(FORMAT)}
            encrypted_key = Encryption.asymmetric_encrypt(json.dumps(key_cipher), fname=None, publickey=peer_pbkey)
            sender_chats[peer]["shared_key"] = shared_key_1
            data_to_send = {
                "cipher": Encryption.sym_encrypt(json.dumps(response), shared_key_1),
                "type": "Exchange",
                "from": username,
                "to": peer,
                "key": encrypted_key
            }

            data_to_send = Encryption.sign(data_to_send, privatekey)
            

            server_cipher = Encryption.sym_encrypt(json.dumps(data_to_send), LTK)

            send(server_cipher)

            response = sock.recv(MAX_SIZE).decode()
            response = Encryption.sym_decrypt(response, LTK)
            response = json.loads(response)
            check, response = Encryption.check_sign(response, server_pkey)
            if check != 0:
                print(bcolors.FAIL+"Server message is not signed correctly!"+bcolors.ENDC)
                
                return -1
            if response["type"] == "ReExchange" and response["to"] == username and response["from"] == peer:
                # print(response["type"])
                cipher = response["cipher"]
                peer_public_df_key = json.loads(Encryption.sym_decrypt(cipher, shared_key_1))['public_df_key']

                # print('Reciever peer public key', peer_public_df_key)
                # print('Reciever shared_key', shared_key_1)
                # print('kire khar', json.loads(peer_public_df_key))
                
                peer_public_df_key = serialization.load_der_public_key(peer_public_df_key.encode(FORMAT))
                sender_chats[peer]["peer_public_df_key"] = peer_public_df_key
            
                next_cipher, next_public_df_key, next_private_df_key = Encryption.get_next_DH_key(parameters, peer_public_df_key, private_df_key)

                sender_chats[peer]["shared_key"] = next_cipher
                sender_chats[peer]['emojis'] = Encryption.emoji_converter(pickle.dumps(next_cipher))
                sender_chats[peer]["public_df_key"] = next_public_df_key
                sender_chats[peer]["private_df_key"] = next_private_df_key

                send_message(peer)
            else:
                print("Error in exchanging keys")
        elif server_response["status"]=="NOT_SUCH_ONLINE_USER" and server_response['nonce'] == nonce + 1:
            print(f"{peer} is not available right now!")
        else:
            return -1

def change_keys():
    global username, password, privatekey, publickey, sender_chats
    nonce = random.randint(100000, 999999)
    new_public_key, new_private_key = Encryption.genkeys(512 * 8)

    try:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        h_password = digest.finalize().hex()
        data_to_send = {
            "type": "change_keys",
            "new_pbkey": Encryption.serialize_public_key(new_public_key),
            "nonce": nonce,
            "user": username,
            "h_password": h_password
        }
        data_to_send = Encryption.sym_encrypt(json.dumps(data_to_send), LTK)
        send(data_to_send)
        response = json.loads(Encryption.sym_decrypt(sock.recv(MAX_SIZE).decode(), LTK))
        check, response = Encryption.check_sign(response, server_pkey)
        if check != 0:
            print(bcolors.FAIL+"Server message is not signed correctly!"+bcolors.ENDC)
            return -1

        returned_nonce = response['nonce']
        if returned_nonce != nonce + 1:
            print("Nonce is not returned correctly!")
            return -1
        
        status = response["status"]
        if status == "SUCC":
            privatekey = new_private_key
            publickey = new_public_key
            save_keys(username, new_public_key, new_private_key)
            sender_chats = {}
            print("Keys are changed successfully!")
        elif status == "FAILED":
            print("Change key is denied by server!")

    except Exception as e:
        print(e)
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0
    

def create_group():
    global server_pkey, username
    nonce = random.randint(100000, 999999)
    group_name = input("Enter the name of your group : ")

    try:
        data_to_send = {
            "type": "create_group",
            "nonce": nonce,
            "username": username,
            "group_name": group_name 
        }
        data_to_send = Encryption.sign(data_to_send, privatekey)
        send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))

    except Exception:
        print(e)
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0


def show_menu():
    global commands
    
    while True:
        # clear_screen()
        print(bcolors.OKBLUE+"\nCOMMANDS - "+bcolors.ENDC)
        for command in commands:
            print(bcolors.OKGREEN+command+bcolors.BOLD+" " + commands[command]+bcolors.ENDC)
        print('\n')
        command = input()
        if command not in commands.keys():
            print(bcolors.FAIL+"Invalid command!"+bcolors.ENDC)
            time.sleep(1)
            continue 
        elif command == ":register":
            register()
        elif command == ':login':
            login()
        elif command == ':showonline':
            show_online()
        elif command == ':logout':
            logout()
        elif command == ':chat':
            initiate_chat()
        elif command == ":change_keys":
            change_keys()
        elif command == ":create_group":
            create_group()


def side_thread(socket, address):
    global sender_chats, in_chat_with

    while True:
        try:
            data = socket.recv(MAX_SIZE).decode()
            plain = Encryption.sym_decrypt(data, LTK)
            plain = json.loads(plain)
            print("log: type ", plain['type'])
            check, plain = Encryption.check_sign(plain, server_pkey)
            if check != 0:
                print(bcolors.FAIL+"Message from peer is not signed correctly!"+bcolors.ENDC)
                continue
            if plain['type'] == 'Exchange':
                cipher = plain['cipher']
                peer_pbkey = Encryption.deserialize_public_key(plain['peer_pbkey'])
                key_cipher = plain['key']
                key_iv = json.loads(Encryption.asymmetric_dycrypt(key_cipher, privatekey))
                
                # Get the shared key
                shared_key = Encryption.gen_sym_key(key_iv['key'].encode(FORMAT), key_iv['iv'].encode(FORMAT))
                cipher_plain = Encryption.sym_decrypt(cipher, shared_key)
                cipher_plain = json.loads(cipher_plain)
                check, cipher_plain = Encryption.check_sign(cipher_plain, peer_pbkey)
                if check != 0:
                    
                    print(bcolors.FAIL+"Message from peer is not signed correctly!"+bcolors.ENDC)
                    continue

                parameters = cipher_plain['parameters']
                peer_public_df_key = cipher_plain['public_df_key']
                peer = cipher_plain['from']
                nonce = cipher_plain['nonce']
                to = cipher_plain['to']
                assert to == username

                new_shared_key, df_public_key = Encryption.get_diffie_hellman_key(parameters, peer_public_df_key)
                

                receiver_chats[peer] = {
                    "peer_pbkey": peer_pbkey,
                    "public_df_key": df_public_key,
                    "peer_public_df_key": peer_public_df_key,
                    "shared_key": new_shared_key,
                    "parameters": parameters
                }

                data_to_peer = {
                    "type": "ReExchange",
                    "status": "SUCC",
                    "nonce": nonce + 1,
                    "from": username,
                    "to": peer,
                    "public_df_key": df_public_key
                }
                data_to_peer = Encryption.sign(data_to_peer, privatekey)
                encrypted_response = Encryption.sym_encrypt(json.dumps(data_to_peer), shared_key)
                data_to_server = {
                    "cipher": encrypted_response,
                    "type": "ReExchange",
                    "from": username,
                    "to": peer
                }

                receiver_chats[peer]["shared_key"] = new_shared_key
                receiver_chats[peer]["public_df_key"] = df_public_key
                receiver_chats[peer]['emojis'] = Encryption.emoji_converter(pickle.dumps(new_shared_key))

                data_to_server = Encryption.sign(data_to_server, privatekey)
                server_cipher = Encryption.sym_encrypt(json.dumps(data_to_server), LTK)
                print("Sending ReExchange to server")
                send(server_cipher)


            elif plain['type'] == 'message':
                
                cipher = plain['cipher']
                from_ = plain['from']
                to = plain['to']
                server_nonce = plain['nonce']
                peer = from_
                assert to == username
                
                shared_key = receiver_chats[peer]['shared_key']
                cipher_plain = Encryption.sym_decrypt(cipher, shared_key)
                cipher_plain = json.loads(cipher_plain)
                peer_public_key = receiver_chats[peer]["peer_pbkey"]
                check, cipher_plain, signature = Encryption.check_sign(cipher_plain, peer_public_key, True)
                if peer not in receiver_chats.keys():
                    print(bcolors.FAIL+"You have not initiated a chat with this user. Please initiate a chat first."+bcolors.ENDC)
                    continue

                if check != 0:
                    print(bcolors.FAIL+"Message from peer is not signed correctly!"+bcolors.ENDC)
                    continue

                peer_msg_type = cipher_plain['type']
                peer = cipher_plain['from']
                peer_to = cipher_plain['to']
                peer_msg = cipher_plain['message']
                peer_nonce = cipher_plain['nonce']
                peer_public_df_key = cipher_plain['new_public_df_key']

                assert peer_msg_type == 'send_message'
                assert peer_to == username

                timestamp = int(time.time())
                save_message_to_database(peer, username, peer_msg, timestamp, signature)
                if peer == in_chat_with:
                    load_chat(peer)

                parameters = receiver_chats[peer]['parameters']
                new_shared_key, df_public_key = Encryption.get_diffie_hellman_key(parameters, peer_public_df_key)

                receiver_chats[peer]["peer_public_df_key"] = peer_public_df_key
                receiver_chats[peer]["shared_key"] = new_shared_key
                receiver_chats[peer]["public_df_key"] = df_public_key
                
                data_to_peer = {
                    "type": "remessage",
                    "status": "SUCC",
                    "nonce": peer_nonce,
                    "from": username,
                    "to": peer,
                    "public_df_key": df_public_key
                }
                data_to_peer = Encryption.sign(data_to_peer, privatekey)
                encrypted_response = Encryption.sym_encrypt(json.dumps(data_to_peer), shared_key)
                data_to_server = {
                    "cipher": encrypted_response,
                    "type": "remessage",
                    "from": username,
                    "to": peer
                }
                data_to_server = Encryption.sign(data_to_server, privatekey)
                server_cipher = Encryption.sym_encrypt(json.dumps(data_to_server), LTK)

                send(server_cipher)


        except Exception as e:
            # raise e
            continue


def listen():

    global username
    
    while True:
        try:
            client_sock, addr = server_sock.accept()
            thr = threading.Thread(target=side_thread, args=(client_sock, addr))
            thr.daemon = True
            thr.start()
        except KeyboardInterrupt:
            print(bcolors.FAIL+"Program terminated by user, see you again :("+bcolors.ENDC)
            sys.exit()




def start_client():
    clear_screen()
    initial_client()

    thr1 = threading.Thread(target=show_menu)
    thr2 = threading.Thread(target=listen)
    
    thr1.daemon = True
    thr2.daemon = True
    thr1.start()
    thr2.start()
    
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print(bcolors.FAIL+"Program terminated by user, see you again :("+bcolors.ENDC)
            sys.exit()




if __name__ == "__main__":
    with open("keys\spubkey.pem", "rb") as key_file:
        server_pkey = serialization.load_pem_public_key(
        key_file.read())
    
    start_client()