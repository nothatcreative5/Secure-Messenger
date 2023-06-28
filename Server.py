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
            public_key,
            salt);
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

def send(resp,c):
    c.sendall(resp.encode())


def register(plain,c):
    conn = sqlite3.connect('users.db')
    uname = plain["username"]
    passwd = plain["password"]
    pub_key = plain["public_key"]

    cursor = conn.execute("SELECT username from users where username='%s'"%(uname))
    rowcount = len(cursor.fetchall())
    
    if len(rowcount) > 0:
        return -1

    else:
        try:
            salt = int.from_bytes(os.urandom(16), byteorder="big")
            salt_pass = f'{passwd}{salt}'.encode()
            h_password = hashlib.sha256(salt_pass).hexdigest()
            conn.execute("INSERT INTO Users(username,h_password,public_key,salt) values('%s','%s','%s','%s')"%(uname,h_password,pub_key,salt))
            conn.commit()
            conn.close()
            authorized_users[uname] = c
            client_keys[uname] = pub_key
            return 0
        except Exception:
            return -1

    # try:

    #     # cursor = conn.execute("SELECT username from users where username='%s'"%(uname))
    #     # rowcount = len(cursor.fetchall())
    #     # print("Number of usrs with the username %s : "%uname,rowcount)
    #     # if(rowcount==1):
    #     #     #User exists
    #     #     outp = "{'resp_type':'FAIL','resp':'Username already exists'}"
    #     #     outp = Payload()
    #     #     outp.type = Payload.Type.Register
    #     #     outp.status = "FAIL"
    #     #     outp.additional_information = "Username already exists"

    #     #     send(outp,c)
    #     # elif(rowcount==0):
    #     #     #Username available
    #     #     conn.execute("INSERT INTO users(username,password) values('%s','%s')"%(uname,passwd))
    #     #     conn.commit()
    #     #     conn.close()
    #     #     authorized_users[uname] = c
    #     #     print("User created!")
    #     #     outp = "{'resp_type':'SUCC','resp':'User created!'}"
    #     #     send(outp,c)
            
        
    # except Exception as e:
    #     print("Error - %s"%e)
    #     outp = b"{'resp_type':'FAIL','resp':'%s'}"%e
    #     send(outp,c)
    #     c.close()

def new_connection(c, a):
    #Accept data from the client
    global authorized_users
    while True:
        try:
            payload = c.recv(1024).decode()
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
                    nonce = plain['nonce']
                    stat = register(plain, c)
                    if(stat == 0):
                        outp = "{'command: 'register', 'status': SUCC, 'nonce': %s}"%nonce
                    else:
                        outp = "{'command: 'register', 'status': FAIL, 'nonce': %s}"%nonce
                    
                    signature = Encryption.signature(outp, private_key)
                    cipher = Encryption.asymmetric_encrypt(outp, fname=None, publickey=client_keys[c])
                    response = {'cipher': cipher, 'signature': signature}
                    send(json.dumps(response), c)

                elif payload['type'] == 'handshake':
                    nonce = payload['nonce']
                    # pkey = Encryption.deserialize_public_key(plain['public_key'].encode())
                    # print(type(pkey))
                    outp = '{"command": "handshake", "status": "SUCC", "nonce": "%s"}'%nonce
                    signature = Encryption.signature(outp, private_key)
                    response = {'cipher': outp, 'signature': signature}
                    send(json.dumps(response), c)
                    print("Finished Handhake")


            except Exception as e:
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