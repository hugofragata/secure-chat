import os, sys
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import string

class User:

    def __init__(self, name):
        self.name = name

        #TODO: manage keys and log in

    def cipher_text(self, text):
        pass

    def sign_text(self, text):
        pass

    def decipher_text(self, text):
        pass

    def validate_source(self, user_source, text):
        pass

    def login(self, user, password):
        pass

    def gen_key_pair(self):
        self.private_key = rsa.generate_private_key(65537, 4096, default_backend())
        self.public_key = self.private_key.public_key()


    def gen_client_random(self):
        return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32))

