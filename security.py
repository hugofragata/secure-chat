import os, sys
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
import string
from hashlib import sha256
import base64

path_to_key = "./key.pem"


class security:

    def __init__(self):
        self.private_key = None
        self.public_key = None


################
#Assymetric cryptography functions
################

    def gen_key_pair(self):

        priv_key = rsa.generate_private_key(65537, 4096, default_backend())
        pub_key = priv_key.public_key()

        return (priv_key, pub_key)

    def load_key_pair(self, path_to_key):

        with open(path_to_key, "rb") as key_file:
            priv_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend())

        pub_key = priv_key.public_key()

        return (priv_key, pub_key)

    def sign_with_private_key(self, text, private_key):

        if not self.private_key or not text:
            raise security_error

        signer = private_key.signer(
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH),
                hashes.SHA256())

        message = str(text)
        signer.update(message)
        signature = signer.finalize()

        return signature

    def verify_with_public_key(self, signature, public_key):

        if not signature or not public_key:
            raise security_error

        #public_key = load_pem_public_key(public_pem_data, backend=default_backend())

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise security_error

        verifier = public_key.verifier(
            signature,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        verifier.update(message)
        try:
            verifier.verify()
        except:
            return False
        else:
            return True

    def encrypt_with_public_key(self, text, public_key):
        cipher_text = public_key.encrypt(text,
                                        padding.OAEP(
                                            mgf = padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm = hashes.SHA1,
                                            label = None))
        return cipher_text

    def decrypt_with_private_key(self, text, private_key):
        plain_text = public_key.encrypt(text,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1,
                                            label=None))
        return plain_text



################
# Symmetric cryptography functions
################

    def generate_key_symmetric(self):
        return Fernet.generate_key()

    def encrypt_with_symmetric(self, text, key):
        f = Fernet(key)
        return  f.encrypt(bytes(base64.encodestring(text)))

    def decrypt_with_symmetric(self, text, key):
        f = Fernet(key)
        return f.decrypt(bytes(base64.decodestring(text)))



class security_error:
    pass