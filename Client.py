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

chats = {}

# Encryption keys
# publickey = None
# privatekey = None

user_keys = {}

username = None

server_pkey = None


def send(resp):
    sock.sendall(resp.encode())

def register():
    global username, commands
    while True:
        uname = input(bcolors.OKBLUE+"Choose a username : "+bcolors.ENDC)
        passwd = getpass.getpass(bcolors.OKBLUE+"Enter Password : "+bcolors.ENDC)
        retype_passwd = getpass.getpass(bcolors.OKBLUE+"Re-type Password : "+bcolors.ENDC)

        if(passwd==retype_passwd):
            break
        else:
            print(bcolors.FAIL+"Passwords do not match, try again."+bcolors.ENDC)

    publickey, privatekey = Encryption.genkeys(512 * 2)

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

        send(Encryption.asymmetric_encrypt(json.dumps(data_to_send), fname=None, publickey=server_pkey))
        '''
        response = {
        cipher: "cipher",
        signature: "signature",
        }
        '''
        response = json.loads(sock.recv(MAX_SIZE).decode())
        plain = Encryption.asymmetric_dycrypt(response["cipher"], privatekey=privatekey)

        signature = response["signature"]


        if response["status"] == "FAIL":
            print(bcolors.FAIL+"Could not register. Please try again."+bcolors.ENDC)
            return -1
        elif Encryption.check_authenticity(plain, signature=signature, public_key=server_pkey) == 0 and \
              json.loads(plain)['nonce'] == "Nonce":
            clear_screen()
            print(bcolors.OKGREEN + f"Successfuly registerd as {uname}" + bcolors.ENDC)
            user_keys[uname] = [publickey, privatekey,None]
            return 0

    except Exception as e:
        print(e)
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0
    

def login():
    global commands, user_keys, username

    uname = input(bcolors.OKBLUE+"Choose a username : "+bcolors.ENDC)
    passwd = getpass.getpass(bcolors.OKBLUE+"Enter Password : "+bcolors.ENDC)

    try:
        key = os.urandom(32)
        iv = os.urandom(16)
        LTK = Encryption.gen_sym_key(key, iv)

        data_to_send = {
            "type": "login",
            "plain": {
            "username": uname,
            "password": passwd,
            "LTK": [key.decode(FORMAT), iv.decode(FORMAT)]
            },
            "nonce": "Nonce"
        }

        send(Encryption.asymmetric_encrypt(json.dumps(data_to_send), fname=None, publickey=server_pkey))
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
            user_keys[uname][2] = LTK
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
    print(data_to_send)
    send(Encryption.asymmetric_encrypt(json.dumps(data_to_send), fname=None, publickey=server_pkey))
    response = json.loads(sock.recv(MAX_SIZE).decode())
    plain = Encryption.sym_decrypt(response["cipher"], LTK)
    plain = json.loads(plain)
    print(plain)
    signature = response["signature"]
    if plain["status"]=="SUCC" and plain['nonce'] == nonce + 1:
        clear_screen()
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
    send(Encryption.asymmetric_encrypt(json.dumps(data_to_send), fname=None, publickey=server_pkey))
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
    os.system('cls' if os.name == 'nt' else 'clear')



# Initial authentication of the server.
def handshake():

    global server_pkey

    data_to_send = {
        "type": "handshake",
        "nonce" : "nonce",
    }

    try: 
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
        return 0


def initial_client():
    global username
    print(bcolors.OKBLUE+"Trying to connect and handshake with the server..."+bcolors.ENDC)
    
    try:
        sock.connect(('127.0.0.1',1600))
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

def handle_chat(socket, address):
    global chats

    while True:
        try:
            data = json.loads(socket.recv(MAX_SIZE).decode())
            if not data:
                break
            print(bcolors.OKGREEN+data.decode()+bcolors.ENDC)

            if data['type'] == 'Exchange':
                plain = Encryption.sym_decrypt(data['cipher'], user_keys[username][2])
                signature = data['signature']
                if Encryption.check_authenticity(plain, signature, user_keys[username][1]) == 0:
                    parameters = plain['parameters']
                    peer = parameters['peer']
                    from_ = parameters['from']
                    pbkey = parameters['pbkey']

                    if peer not in chats:
                        shared_key, new_pbkey = Encryption.get_diffie_hellman_key(parameters ,pbkey)
                        # Messages and current key
                        chats[peer] = [[], shared_key] 
                        output = {
                            "type": "Exchange",
                            'pbkey' : new_pbkey,
                            'from' : peer,
                            'peer' : from_,
                        }
                        output = json.dumps(output)
                        output = Encryption.sym_encrypt(output, shared_key)
                        socket.sendall(output.encode())
                else:
                    print(bcolors.FAIL+"Authentication failed!"+bcolors.ENDC)
                    break
            elif data['type'] == 'Chat':
                # Same as before just now we have to decrypt the message
                pass
        except Exception as e:
            break


def listen():

    global username
    
    while True:
        try:
            client_sock, addr = server_sock.accept()
            thr = threading.Thread(target=handle_chat, args=(client_sock, addr))
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
