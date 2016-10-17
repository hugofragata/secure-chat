import os, sys

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
