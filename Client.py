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

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

chats = {}

# Encryption keys
publickey = None
privatekey = None
username = None

server_pkey = None

def login():
    pass

def register():
    global username
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
            "public_key": Encryption.serialize_public_key(publickey),
            "Nonce": "Nonce",
            }
        }
        # data_to_send = "{'cmd':'register','uname':'%s','passwd':'%s'}"%(uname,passwd)
        # cipher = encryption.encrypt(data_to_send,"serverkey.pem",publickey=None) #encrypt with server's public key
        # signature = encryption.signature(data_to_send,"keypriv")
        # outp = "{'cipher':%s,'signature':%s}"%(data_to_send,data_to_send)

        sock.send(Encryption.asymmetric_encrypt(json.dumps(data_to_send), fname=None, publickey=server_pkey))
        response = json.loads(sock.recv(2048).decode())
        if(response["status"]=="SUCC"):
            print(bcolors.OKGREEN + f"Successfuly registerd as {uname}" + bcolors.ENDC)
            return 0
        else:
            print(bcolors.FAIL+"Could not register. Please try again."+bcolors.ENDC)
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
    pass
    # os.system('cls' if os.name == 'nt' else 'clear')


def handshake():

    sock.connect(('127.0.0.1',1600))

    global publickey, privatekey, server_pkey

    publickey, privatekey = Encryption.genkeys()

    data_to_send = {
        "type": "handshake",
        "public_key": Encryption.serialize_public_key(publickey).decode(),
    }

    try: 
        sock.send(Encryption.asymmetric_encrypt(json.dumps(data_to_send), fname=None, publickey=server_pkey))
        response = json.loads(sock.recv(2048).decode())
        plain = Encryption.asymmetric_decrypt(response["cipher"], fname=None, privatekey=privatekey)
        signature = response["signature"]
        if Encryption.verify_signature(plain, signature, fname=None, publickey=server_pkey) == 0:
            return 1
        else:
            return 0

    except Exception as e:
        print(e)
        return 0


def initial_client():
    global username
    clear_screen()
    print(bcolors.OKBLUE+"Trying to connect and handshake with the server..."+bcolors.ENDC)
    
    try:
        server_sock.bind(('127.0.0.1',0))
        server_sock.listen(10)
    except Exception as e:
        print(bcolors.FAIL+"Couldn't start the client!"+bcolors.ENDC)
        print(e)
        sys.exit(0)
    
    try:
        addr = sys.argv[1]
        sock.connect((addr,1600))
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
def show_menu(menu):
    global commands

    clear_screen()
    print(bcolors.OKBLUE+"\nCOMMANDS - "+bcolors.ENDC)
    
    while True:
        clear_screen()
        print(bcolors.OKBLUE+"\nCOMMANDS - "+bcolors.ENDC)
        for command in commands:
            print(bcolors.OKGREEN+command+bcolors.BOLD+menu[command]+bcolors.ENDC)
        print('\n')
        command = input()
        if command == ":register":
            register()
        else:
            print(bcolors.FAIL+"Invalid command!"+bcolors.ENDC)
            time.sleep(1)
            continue



def start_client():
    clear_screen()
    handshake()




if __name__ == "__main__":
    with open("spubkey.pem", "rb") as key_file:
        server_pkey = serialization.load_pem_public_key(
        key_file.read())
    
    start_client()

