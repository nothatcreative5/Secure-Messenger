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
publickey = None
privatekey = None
username = None

LTK = None

server_pkey = None

def login():
    pass


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


        if Encryption.check_authenticity(plain, signature=signature, public_key=server_pkey) == 0 and \
        json.loads(plain)["status"]=="SUCC" and json.loads(plain)['nonce'] == "Nonce":
            clear_screen()
            print(bcolors.OKGREEN + f"Successfuly registerd as {uname}" + bcolors.ENDC)
            return 0
        else:
            print(bcolors.FAIL+"Could not register. Please try again."+bcolors.ENDC)
            return -1
    except Exception as e:
        print(e)
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0
    

def login():
    global LTK, commands

    uname = input(bcolors.OKBLUE+"Choose a username : "+bcolors.ENDC)
    passwd = getpass.getpass(bcolors.OKBLUE+"Enter Password : "+bcolors.ENDC)

    try:
        key = os.urandom(32)
        nonce = os.urandom(16)
        LTK = Encryption.gen_sym_key(key, nonce)

        data_to_send = {
            "type": "login",
            "plain": {
            "username": uname,
            "password": passwd,
            "LTK": [key.decode(FORMAT), nonce.decode(FORMAT)]
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
        # plain = Encryption.asymmetric_dycrypt(response["cipher"], privatekey=privatekey)
        plain = Encryption.sym_decrypt(response["cipher"], LTK)

        print(json.loads(plain)["status"])
        print('kir')

        signature = response["signature"]

        if Encryption.check_authenticity(plain, signature=signature, public_key=server_pkey) == 0 and \
        json.loads(plain)["status"]=="SUCC" and json.loads(plain)['nonce'] == "Nonce":
            clear_screen()
            print(bcolors.OKGREEN + f"Successfuly logged in as {uname}" + bcolors.ENDC)
            commands = account_page.copy()
            return 0
        else:
            print(bcolors.FAIL+"Could not login. Please try again."+bcolors.ENDC)
            return -1
    except Exception as e:
        print(e)
        print(bcolors.FAIL+"Couldn't communicate with the server :("+bcolors.ENDC)
        return 0


    


main_page = {":login" : "Login to an existing account", ":register" : "Create an account"}
main_page_func = {":login" : login, ":register" : register}
account_page = {":chat" : "Chat with an online user",":showonline" : "Show online users", ":logout" : "Logout from the account"}


commands = main_page.copy()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')



# Initial authentication of the server.
def handshake():

    global publickey, privatekey, server_pkey

    publickey, privatekey = Encryption.genkeys(512 * 2)

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
    clear_screen()
    print(bcolors.OKBLUE+"Trying to connect and handshake with the server..."+bcolors.ENDC)
    
    try:
        sock.connect(('127.0.0.1',1600))
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



def start_client():
    clear_screen()
    initial_client()
    show_menu()




if __name__ == "__main__":
    with open("spubkey.pem", "rb") as key_file:
        server_pkey = serialization.load_pem_public_key(
        key_file.read())
    
    start_client()
