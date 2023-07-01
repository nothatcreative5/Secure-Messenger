from cryptography.hazmat.primitives import serialization
import random


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

def get_nonce():
    return random.randint(100000, 999999)

 
def genkeys(size):
    # Generate public and private key pair.

    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=size,)

    public_key = private_key.public_key()

    return public_key, private_key

def cipher_from_hash(pass_hash):
    pass_hash = pass_hash.finalize()
    key = pass_hash
    iv = pass_hash[:16]
    return gen_sym_key(key, iv)

def diffie_first_step():
    # Generate Diffie-Hellman parameters and public key.

    parameters = dh.generate_parameters(generator=2, key_size=512, backend=None)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return parameters, public_key, private_key

def get_next_DH_key(parameters, peer_public_bkey, private_key):
    shared_key = private_key.exchange(peer_public_bkey)

    cipher = gen_sym_key(shared_key[:32], shared_key[32:48])

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return cipher, public_key.public_bytes( encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(FORMAT), private_key


def get_diffie_hellman_key(parameters, pbkey):
    p, g = parameters
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters()
    pbkey = serialization.load_der_public_key(pbkey.encode(FORMAT))

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    shared_key = private_key.exchange(pbkey)

    cipher = gen_sym_key(shared_key[:32], shared_key[32:48])

    return cipher, public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(FORMAT)


    
def asymmetric_encrypt(text, fname, publickey):
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