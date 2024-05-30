import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def key_generator(salt, password):

    kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32, 
            salt = salt,
            iterations = 480000,
        )

    return kdf.derive(password)


def enc(file,file_data, password):
    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = key_generator(salt,password)

    algorithm = ChaCha20Poly1305(key)
    
    try:
        ct = algorithm.encrypt(nonce, file_data, None)
        with open(f"{file}", "wb") as encrypted_file:
            encrypted_file.write(salt + nonce + ct)
    except: 
        print("\033[31m[ERROR] Impossible to encrypt file\033[m")



def dec(file,password):
    with open(file, "rb") as f:
        salt = f.read(16)
        nonce = f.read(12)
        ct = f.read()

    key = key_generator(salt,password)
    
    algorithm = ChaCha20Poly1305(key)

    try:
        return algorithm.decrypt(nonce, ct, None)
    except:
        print("\033[31m[ERROR] Invalide password or file corrupted\033[m")

