import socket
import threading
import ast
import sqlite3
import os.path
from os import path
import codecs
import hashlib
import Encryption
import Payload
import sys
from cryptography.hazmat.primitives import serialization
import json
from Colors import bcolors

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

sock.bind(('',1600))
sock.listen(10)

pub_key = None
private_key = None
MAX_SIZE = 65536

FORMAT = 'latin-1'

connections = list()
authorized_users = dict()
client_keys= dict()

def makedb():
    if(path.exists("users.db")):
        return 1
    else:
        conn = sqlite3.connect('users.db')
        cur = conn.cursor()
        sql = '''
        CREATE TABLE IF NOT EXISTS Users(
            username NOT NULL PRIMARY KEY,
            password,
            public_key);
        CREATE TABLE IF NOT EXISTS Messages(
            user1,
            user2,
            encrypted_msg,
            signature,
            time,
            FOREIGN KEY(user1) REFERENCES Users(username),
            FOREIGN KEY(user2) REFERENCES Users(username));
        CREATE TABLE IF NOT EXISTS Groups(
            group_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            owner,
            FOREIGN KEY(owner) REFERENCES Users(username));
        CREATE TABLE IF NOT EXISTS Group_Members(
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY(user_id) REFERENCES Users(username),
            FOREIGN KEY(group_id) REFERENCES Groups(group_id));
        
        '''
        cur.executescript(sql)
        conn.close()

def get_pbkey(uname):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    sql = "SELECT public_key from Users where username='%s'"%uname
    cur.execute(sql)
    pbkey = cur.fetchone()[0]
    conn.close()
    return Encryption.deserialize_public_key(pbkey)

def send(resp,c):
    c.sendall(resp.encode())


def register(uname, passwd, pub_key):
    # sys.exit(-1)
    conn = sqlite3.connect('users.db')

    cursor = conn.execute("SELECT username from users where username='%s'"%(uname))
    rowcount = len(cursor.fetchall())

    # sys.exit(-1)
    
    if rowcount > 0:
        return -1

    else:
        try:
            # Server is secure, so why?
            # salt = int.from_bytes(os.urandom(16), byteorder="big")
            # salt_pass = f'{passwd}{salt}'.encode()
            # h_password = hashlib.sha256(salt_pass).hexdigest()
            conn.execute("INSERT INTO Users(username,password,public_key) values('%s','%s','%s')"%(uname,passwd,pub_key))
            conn.commit()
            conn.close()

            return get_pbkey(uname)
        except Exception:
            return None
        

def login(uname, passwd):
    conn = sqlite3.connect('users.db')
    cursor = conn.execute("SELECT username from users where username='%s' and password='%s'"%(uname,passwd))
    rowcount = len(cursor.fetchall())
    conn.close()
    if rowcount > 0:
        return 1
    else:
        return 0


def new_connection(c, a):
    #Accept data from the client
    global authorized_users, client_keys
    while True:
        try:
            payload = c.recv(MAX_SIZE).decode()
            # payload = json.loads(c.recv(1024).decode())
        except Exception as e:
            print("Error - %s"%e)
            exit(-1)
            
        # Currently makes no sense
        if(not(payload)):
            print("Connection closed by client.\n")
            del connections[connections.index(c)]
            authorized_users = {k: v for k, v in authorized_users.items() if v != c}
            break

        else:
            try:
                payload = json.loads(Encryption.asymmetric_dycrypt(payload, private_key))
                if payload['type'] == 'register':
                    plain = payload['plain']
                    nonce = payload['nonce']
                    pbkey = register(plain['username'], plain['password'], plain['pbkey'])

                    outp = {
                        'command': 'register',
                        'status': 'SUCC',
                        'nonce': nonce
                    }
                    # pbkey = Encryption.deserialize_public_key(plain["pbkey"])

                    if pbkey is None: 
                        print('Failed to register user')
                        return -1
                    
                    signature = Encryption.signature(json.dumps(outp), private_key)
                    cipher = Encryption.asymmetric_encrypt(json.dumps(outp), fname=None, publickey=pbkey)
                    response = {'cipher': cipher, 'signature': signature}
                    send(json.dumps(response), c)
                    print('User registered successfully!')

                elif payload['type'] == 'login':
                    plain = payload['plain']
                    [key, nonce] = plain['LTK']
                    key = key.encode(FORMAT)
                    nonce = nonce.encode(FORMAT) 

                    LTK = Encryption.gen_sym_key(key, nonce)
                    
                    nonce = payload['nonce']
                    uname = plain['username']

                    result = login(plain['username'], plain['password'])

                    outp = {
                        'command': 'login',
                        'status': 'SUCC',
                        'nonce': nonce
                    }

                    if result == 1:
                        client_keys[uname] = LTK
                        authorized_users[uname] = c
                    
                    signature = Encryption.signature(json.dumps(outp), private_key)
                    cipher = Encryption.sym_encrypt(json.dumps(outp), LTK)
                    response = {'cipher': cipher, 'signature': signature}
                    send(json.dumps(response), c)
                    print('User logged in successfully!')
                    


                        



                elif payload['type'] == 'handshake':
                    nonce = payload['nonce']
                    outp = '{"command": "handshake", "status": "SUCC", "nonce": "%s"}'%nonce
                    signature = Encryption.signature(outp, private_key)
                    response = {'cipher': outp, 'signature': signature}
                    send(json.dumps(response), c)
                    print("Finished Handhake")


            except Exception as e:
                raise e
                print("Error - %s"%e)
                exit(-1)


if __name__ == "__main__":
    makedb()
    pub_key, private_key =  Encryption.genkeys(4096)
    pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1)
    f = open("spubkey.pem","wb")
    f.write(pem)
    f.close()
    
    while True:
        c,a = sock.accept()
        connections.append(c)
        thr = threading.Thread(target=new_connection,args=(c,a))
        thr.daemon = True
        thr.start()