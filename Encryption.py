import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import ast
import hashlib
from cryptography.hazmat.primitives import serialization
import codecs
from base64 import (
    b64encode,
    b64decode,
)


FORMAT = 'latin-1'


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

 
def genkeys(size):
    # Generate public and private key pair.

    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=size,)

    public_key = private_key.public_key()

    return public_key, private_key


def symmetric_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text)
    return ciphertext, tag, cipher.nonce

def symmetric_decrypt(ciphertext, tag, nonce, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        print("Key incorrect or message corrupted")
        return None
 
    
def asymmetric_encrypt(text,fname,publickey):

    ciphertext = publickey.encrypt(
    text.encode(FORMAT),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return ciphertext.decode(FORMAT)
    
def asymmetric_dycrypt(cipher,privatekey):
    cipher = cipher.encode(FORMAT)
    plaintext = privatekey.decrypt(
    cipher,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return plaintext.decode(FORMAT)


def hash_string(text):
    digest = SHA256.new()
    digest.update(text)
    return digest

def signature(text, private):
    signature = private.sign(
    text.encode(FORMAT),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256())

    return signature.decode(FORMAT)
    

def check_authenticity(text,signature,public_key):
    try:
        # text = text.encode(FORMAT)
        public_key.verify(
        signature.encode(FORMAT),
        text.encode(FORMAT),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
        return 0
    except Exception as e:
        return -1
    

def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1)
    
    return pem

def deserialize_public_key(public_key):
    return serialization.load_pem_public_key(public_key) 
    

    
