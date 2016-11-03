import os, sys
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import string
from hashlib import sha256
import base64

path_to_key = "./key.pem"

CIPHER_SUITE_A = "RSA_WITH_AES_128_CBC_SHA256"
CIPHER_SUITE_B = "ECDHE_WITH_AES_128_CBC_SHA256"

class security:

    def __init__(self):
        pass


################
#Assymetric cryptography functions
################



    def ecdh_gen_key_pair(self):

        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        peer_public_key = ec.generate_private_key(ec.SECP384R1(), default_backend()).public_key()

        return (private_key, peer_public_key)

    def ecdh_get_shared_secret(self, partner_public_key):
        shared_key = private_key.exchange(ec.ECDH(), partner_public_key)

        return shared_key

    def rsa_gen_key_pair(self):

        priv_key = rsa.generate_private_key(65537, 4096, default_backend())
        pub_key = priv_key.public_key()

        return (priv_key, pub_key)

    def rsa_load_key_pair(self, path_to_key):

        with open(path_to_key, "rb") as key_file:
            priv_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend())

        pub_key = priv_key.public_key()

        return (priv_key, pub_key)

    def rsa_sign_with_private_key(self, text, private_key):

        if not private_key or not text:
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

    def rsa_verify_with_public_key(self, signature, public_key):

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

    def rsa_encrypt_with_public_key(self, text, public_key):
        cipher_text = public_key.encrypt(text,
                                        padding.OAEP(
                                            mgf = padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm = hashes.SHA1,
                                            label = None))
        return cipher_text

    def rsa_decrypt_with_private_key(self, text, private_key):
        plain_text = private_key.decrypt(text,
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

    def derive_symmetric_key(self, original_key):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            iterations = 100000,
            backend = default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(original_key))
        return (Fernet(key), str(salt))

    def get_derived_symmetric_key(self, original_key, salt):

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(original_key))

        return Fernet(key)

class security_error:
    pass