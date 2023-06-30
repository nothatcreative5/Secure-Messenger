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
from cryptography.hazmat.primitives import hashes
import json
from Colors import bcolors

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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
            h_password,
            public_key
            );
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
    cur.execute("SELECT public_key from Users where username='%s'"%(uname))
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

            digest = hashes.Hash(hashes.SHA256())
            digest.update(passwd.encode())
            h_password = digest.finalize().hex()

            print(h_password)

            conn.execute("INSERT INTO Users(username,h_password,public_key) values('%s','%s','%s')"%(uname,h_password,pub_key))
            conn.commit()
            conn.close()

            return get_pbkey(uname)
        except Exception:
            return None
        

def login(uname, passwd):
    conn = sqlite3.connect('users.db')

    digest = hashes.Hash(hashes.SHA256())
    digest.update(passwd.encode())
    h_password = digest.finalize().hex()

    cursor = conn.execute("SELECT username from users where username='%s' and h_password='%s'"%(uname,h_password))
    rowcount = len(cursor.fetchall())
    conn.close()
    if rowcount > 0:
        return 1
    else:
        return 0


def new_connection(c, a):
    global authorized_users, client_keys
    while True:
        try:
            payload = c.recv(MAX_SIZE).decode()
            # payload = json.loads(c.recv(1024).decode())
        except Exception as e:
            sock.close()
            print("Error - %s"%e)
            exit(-1)
            
        # Currently makes no sense
        if(not(payload)):
            print("Connection closed by client.\n")
            del connections[connections.index(c)]
            del client_keys[c]
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
                        'nonce': nonce
                    }
                    # pbkey = Encryption.deserialize_public_key(plain["pbkey"])

                    if pbkey is None: 
                        response  
                        print('Failed to register user')
                        return -1
                    
                    signature = Encryption.signature(json.dumps(outp), private_key)
                    cipher = Encryption.asymmetric_encrypt(json.dumps(outp), fname=None, publickey=pbkey)
                    response = {'cipher': cipher, 'signature': signature, 'status' : 'SUCC'}
                    send(json.dumps(response), c)
                    print('User registered successfully!')

                elif payload['type'] == 'login':

                    plain = payload['plain']
                    nonce = payload['nonce']
                    uname = plain['username']

                    if uname in authorized_users:
                        response = {'cipher': "", 'signature': "", 'status' : 'FAIL'}
                    else:
                        [key, iv] = plain['LTK']
                        key = key.encode(FORMAT)
                        iv = iv.encode(FORMAT) 

                        LTK = Encryption.gen_sym_key(key, iv)
                        
                        result = login(plain['username'], plain['password'])

                        outp = {
                            'command': 'login',
                            'nonce': nonce
                        }

                        if result == 1:
                            client_keys[c] = LTK
                            authorized_users[uname] = c
                            signature = Encryption.signature(json.dumps(outp), private_key)
                            cipher = Encryption.sym_encrypt(json.dumps(outp), LTK)
                            response = {'cipher': cipher, 'signature': signature, 'status' : 'SUCC'}
                        else:
                            response = {'cipher': "", 'signature': "", 'status' : 'FAIL'}

                    send(json.dumps(response), c)
                
                elif payload['type'] == 'show_online':
                    username = payload['user']
                    client_key = client_keys[c]
                    nonce = int(payload['nonce'])
                    online_users = list(authorized_users.keys())
                    outp = {
                        'command': 'show_online',
                        'status': 'SUCC',
                        'nonce': nonce+1,
                        'online_users': online_users
                    }
                    pbkey = get_pbkey(username)
                    signature = Encryption.signature(json.dumps(outp), private_key)
                    cipher = Encryption.sym_encrypt(json.dumps(outp), client_key)
                    response = {'cipher': cipher, 'signature': signature}
                    send(json.dumps(response), c)
                    print('Online users sent successfully!')
                
                elif payload['type'] == 'logout':
                    username = payload['user']
                    client_key = client_keys[c]
                    nonce = int(payload['nonce'])
                    outp = {
                        'command': 'logout',
                        'status': 'SUCC',
                        'nonce': nonce+1
                    }
                    signature = Encryption.signature(json.dumps(outp), private_key)
                    cipher = Encryption.sym_encrypt(json.dumps(outp), client_key)
                    response = {'cipher': cipher, 'signature': signature}
                    send(json.dumps(response), c)
                    del connections[connections.index(c)]
                    authorized_users = {k: v for k, v in authorized_users.items() if v != c}
                    print('User logged out successfully!')

                elif payload['type'] == 'handshake':
                    nonce = payload['nonce']
                    outp = '{"command": "handshake", "status": "SUCC", "nonce": "%s"}'%nonce
                    signature = Encryption.signature(outp, private_key)
                    response = {'cipher': outp, 'signature': signature}
                    send(json.dumps(response), c)
                    print("Finished Handhake")

                elif payload['type'] == "initiate_chat":
                    peer = payload['peer']
                    nonce = payload['nonce']
                    from_ = payload['from']

                    peer_pbkey = get_pbkey(peer)

                    response = {
                        'command': 'initiate_chat',
                        'status': 'SUCC',
                        'nonce': nonce+1,
                        'peer_pbkey': peer_pbkey,
                    }
                    client_key = client_keys[c]
                    signature = Encryption.signature(json.dumps(response), private_key)
                    cipher = Encryption.asymmetric_encrypt(json.dumps(response), fname=None, publickey=client_key)
                    response = {'cipher': cipher, 'signature': signature}
                    send(json.dumps(response), c)



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