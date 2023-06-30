import ast
import hashlib
from cryptography.hazmat.primitives import serialization
import codecs
import json


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from base64 import (
    b64encode,
    b64decode,
)


FORMAT = 'latin-1'


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

 
def genkeys(size):
    # Generate public and private key pair.

    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=size,)

    public_key = private_key.public_key()

    return public_key, private_key


def diffie_first_step():
    # Generate Diffie-Hellman parameters and public key.

    parameters = dh.generate_parameters(generator=2, key_size=512, backend=None)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return parameters, public_key, private_key



def get_diffie_hellman_key(parameters, pbkey):
    p, g = parameters
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters()
    pbkey = serialization.load_der_public_key(pbkey.encode(FORMAT))

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    shared_key = private_key.exchange(pbkey)

    cipher = gen_sym_key(shared_key[:32], shared_key[32:])

    return cipher, public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(FORMAT)






    
def asymmetric_encrypt(text, fname, publickey, max_size=128):
    chunks = [text[i:i+max_size] for i in range(0, len(text), max_size)]
    ciphertext = []
    for chunk in chunks:
        # chunk = json.dumps(chunk)
        chunk_ciphertext = publickey.encrypt(
            chunk.encode(FORMAT),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        ciphertext.append(chunk_ciphertext.decode(FORMAT))
    return json.dumps(ciphertext)
    
def asymmetric_dycrypt(cipher, privatekey, max_size=128):
    plaintext = ''
    cipher = json.loads(cipher)
    for chunk in cipher:
        plaintext_chunk = privatekey.decrypt(
            chunk.encode(FORMAT),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        plaintext += plaintext_chunk.decode(FORMAT)
    return plaintext



def signature(text, private):
    signature = private.sign(
    text.encode(FORMAT),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256())

    return signature.decode(FORMAT)
    

def check_authenticity(text, signature, public_key):
    try:
        public_key.verify(
        signature.encode(FORMAT),
        text.encode(FORMAT),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
        return 0
    except Exception:
        return -1
    

def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1)
    
    return pem.decode(FORMAT)

def deserialize_public_key(public_key):
    public_key = public_key.encode(FORMAT)
    return serialization.load_pem_public_key(public_key) 
    


def gen_sym_key(key, iv):
    # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

    algorithm = algorithms.ChaCha20(key, iv)
    cipher = Cipher(algorithm, mode=None)

    return cipher


def sym_encrypt(text, cipher):
    text = text.encode(FORMAT)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text) + encryptor.finalize()
    return ciphertext.decode(FORMAT)

def sym_decrypt(ciphertext, cipher):
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext.encode(FORMAT))
    return plaintext.decode(FORMAT)