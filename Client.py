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
from Colors import bcolors
import json


from cryptography.hazmat.primitives import serialization


# Global variables

HOST = '127.0.0.1'
username = ""
password = ""
MAX_SIZE = 65536


FORMAT = 'latin-1'

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

sender_chats = {}
receiver_chats = {}

# Encryption keys
publickey = None
privatekey = None
username = None
server_pkey = None
LTK = None

def send(resp):
    sock.sendall(resp.encode())

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

    try:
        data_to_send = {
            "type": "register",
            "plain": {
            "username": uname,
            "password": passwd,
            "pbkey": Encryption.serialize_public_key(publickey),
            },
            "nonce": "Nonce"
        }

        send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))
        '''
        response = {
        cipher: "cipher",
        signature: "signature",
        }
        '''
        response = json.loads(sock.recv(MAX_SIZE).decode())
        plain = Encryption.sym_decrypt(response["cipher"], LTK)

        if response["status"] == "FAIL":
            print(bcolors.FAIL+"Could not register. Please try again."+bcolors.ENDC)
            return -1
        elif json.loads(plain)['nonce'] == "Nonce":
            clear_screen()
            print(bcolors.OKGREEN + f"Successfuly registerd as {uname}" + bcolors.ENDC)
            return 0

    except Exception as e:
        print(e)
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0
    

def login():
    global commands, username

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
            username = uname
            commands = account_page.copy()
            return 0
        else:
            print(bcolors.FAIL+"Could not login. Please try again."+bcolors.ENDC)
            return -1
    except Exception as e:
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0


def show_online():
    global server_pkey
    nonce = random.randint(100000, 999999)
    data_to_send = {
        "type": "show_online",
        "nonce": nonce,
        "user": username
    }
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
    send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))
    response = json.loads(sock.recv(MAX_SIZE).decode())
    plain = Encryption.sym_decrypt(response["cipher"], LTK)
    plain = json.loads(plain)
    signature = response["signature"]
    if plain["status"]=="SUCC" and plain['nonce'] == nonce + 1:
        clear_screen()
        print(bcolors.OKGREEN + f"Successfuly logged out." + bcolors.ENDC)
        commands = main_page.copy()
        return 0
    else:
        print(bcolors.FAIL+"Could not logout. Please try again."+bcolors.ENDC)
        return -1
    


main_page = {":login" : "Login to an existing account", ":register" : "Create an account"}
main_page_func = {":login" : login, ":register" : register}
account_page = {":chat" : "Chat with an online user",":showonline" : "Show online users", ":logout" : "Logout from the account"}


commands = main_page.copy()

def clear_screen():
    pass
    # os.system('cls' if os.name == 'nt' else 'clear')



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
        print(response, plain, Encryption.check_authenticity(response['cipher'], signature,server_pkey))
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
        sock.connect(('127.0.0.1',19000))
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
    clear_screen()
    #TODO: read from database and show the chat
    pass

def send_message(peer):
    global username, server_pke
    
    load_chat(peer)

    while True:
        msg = input()
        if msg == ":back":
            break
        else:
            nonce = random.randint(100000, 999999)
            data_to_peer = {
                "type": "send_message",
                "nonce": nonce,
                "from": username,
                "to": peer,
                "message": msg
            }
            encrypted_data_to_peer = Encryption.sym_encrypt(json.dumps(data_to_peer), sender_chats[peer]["shared_key"])

            data_to_send = {
                "type": "send_message",
                "nonce": nonce,
                "from": username,
                "to": peer,
                "cipher": encrypted_data_to_peer
            }
            encrypted_data_to_send = Encryption.sym_encrypt(json.dumps(data_to_send), LTK)

            send(encrypted_data_to_send)
    
    return 0






def initiate_chat():
    global server_pkey, username
    nonce = random.randint(100000, 999999)
    peer = input("Enter the username of the user you want to chat with : ")
    data_to_send = {
        "type": "initiate_chat",
        "nonce": nonce,
        "from": username,
        "peer": peer 
    }
    send(Encryption.sym_encrypt(json.dumps(data_to_send), LTK))
    response = json.loads(sock.recv(MAX_SIZE).decode())
    plain = Encryption.sym_decrypt(response["cipher"], LTK)
    plain = json.loads(plain)

    peer_pbkey = plain["peer_pbkey"]

    signature = response["signature"]
    if plain["status"]=="SUCC" and plain['nonce'] == nonce + 1:
        print('HABIBI')
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


        # signature = Encryption.signature(json.dumps(response), user_keys[username][1])
        # print(signature)
        

        server_cipher = Encryption.sym_encrypt(json.dumps(data_to_send), LTK)

        send(server_cipher)

        response = json.loads(sock.recv(MAX_SIZE).decode())
        response = Encryption.sym_decrypt(response, LTK)
        if response["type"] == "ReExchange" and response["to"] == username and response["from"] == peer:
            print(response["type"])
            cipher = response["cipher"]
            peer_public_df_key = Encryption.sym_decrypt(cipher, shared_key_1)

            sender_chats[peer]["peer_public_df_key"] = peer_public_df_key
        
            next_cipher, next_public_df_key, next_private_df_key = Encryption.diffie_second_step(parameters, peer_public_df_key, private_df_key)

            sender_chats[peer]["shared_key"] = next_cipher
            sender_chats[peer]["public_df_key"] = next_public_df_key
            sender_chats[peer]["private_df_key"] = next_private_df_key

            send_message(peer)
        else:
            print("Error in exchanging keys")


        print(bcolors.OKGREEN + f"Online users : {', '.join(plain['online_users'])}" + bcolors.ENDC)
    else:
        # print(bcolors.FAIL+"Could not get online users. Please try again."+bcolors.ENDC)
        return -1


# Menu is a dictionary of commmands and their descriptions
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

def side_thread(socket, address):
    global sender_chats

    while True:
        try:
            data = socket.recv(MAX_SIZE).decode()
            plain = Encryption.sym_decrypt(data, LTK)
            plain = json.loads(plain)
            if plain['type'] == 'Exchange':
                cipher = plain['cipher']
                peer_pbkey = plain['peer_pbkey']
                key_cipher = plain['key']
                key_iv = json.loads(Encryption.asymmetric_dycrypt(key_cipher, privatekey))
                
                # Get the shared key
                shared_key = Encryption.gen_sym_key(key_iv['key'].encode(FORMAT), key_iv['iv'].encode(FORMAT))
                cipher_plain = Encryption.sym_decrypt(cipher, shared_key)
                cipher_plain = json.loads(cipher_plain)
                parameters = cipher_plain['parameters']
                peer_public_df_key = cipher_plain['public_df_key']
                peer = cipher_plain['from']
                nonce = cipher_plain['nonce']
                to = cipher_plain['to']
                new_shared_key, df_public_key = Encryption.get_diffie_hellman_key(parameters, peer_public_df_key)
                assert to == username

                receiver_chats[peer] = {
                    "peer_pbkey": peer_pbkey,
                    "public_df_key": df_public_key,
                    "peer_public_df_key": peer_public_df_key,
                    "shared_key": new_shared_key,
                    "parameters": parameters
                }

                response = {
                    "type": "ReExchange",
                    "status": "SUCC",
                    "nonce": nonce + 1,
                    "public_df_key": df_public_key
                }

                encrypted_response = Encryption.sym_encrypt(json.dumps(response), shared_key)
                data_to_send = {
                    "cipher": encrypted_response,
                    "type": "ReExchange",
                    "from": username,
                    "to": peer
                }

                server_cipher = Encryption.sym_encrypt(json.dumps(data_to_send), LTK)

                send(server_cipher)

                print(bcolors.OKGREEN+json.dumps(plain)+bcolors.ENDC)

            elif data['type'] == 'Chat':
                # Same as before just now we have to decrypt the message
                pass
        except Exception as e:
            raise e


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
    with open("spubkey.pem", "rb") as key_file:
        server_pkey = serialization.load_pem_public_key(
        key_file.read())
    
    start_client()
