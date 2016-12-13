import os
import random

import urandom
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

path_to_key = "./key.pem"
SUPPORTED_CIPHER_SUITES = ["RSA_WITH_AES_128_CBC_SHA256", "ECDHE_WITH_AES_128_CBC_SHA256", "NONE"]


#TODO 1 shouldn't be a class, should be a set of fucntions only
#TODO 2 when security module is called remove the instance
class security:
    def __init__(self):
        pass
################
#Assymetric cryptography functions
################

    def ecdh_gen_key_pair(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        peer_public_key = private_key.public_key()
        return (private_key, peer_public_key)

    def ecdh_get_shared_secret(self, private_key, partner_public_key):
        shared_key = private_key.exchange(ec.ECDH(), partner_public_key)
        shared_key = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=32,
            otherinfo=None,
            backend=default_backend()
        ).derive(shared_key)
        return base64.urlsafe_b64encode(shared_key)

    def rsa_private_pem_to_key(self, pem):
        private_key = serialization.load_pem_private_key(
            pem,
            password=None,
            backend=default_backend())
        return private_key

    def rsa_public_pem_to_key(self, pem):
        public_key = serialization.load_pem_public_key(
            pem,
            backend=default_backend())
        return public_key

    def rsa_public_key_to_pem(self, public_key):
        pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem

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

    def rsa_verify_with_public_key(self, signature, message, public_key):
        if not signature or not public_key:
            raise security_error
        #public_key = load_pem_public_key(public_pem_data, backend=default_backend())
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise security_error
        signature = str(base64.decodestring(signature))
        message = str(unicode(message))
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
        #if not isinstance(public_key, rsa.RSAPublicKey):
        #    raise security_error
        cipher_text = public_key.encrypt(text,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None))
        return cipher_text

    def rsa_decrypt_with_private_key(self, text, private_key):
        plain_text = private_key.decrypt(text,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None))
        return plain_text

    def verify_self_signed_cert(self, cert):
        '''
        Verifies whether a provided certificate is valid
        :param cert: The to-be validated certificate in PEM format
        :return: True or False
        '''
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        store = crypto.X509Store()
        store.add_cert(certificate)
        try:
            crypto.X509StoreContext(store, certificate).verify_certificate()
        except crypto.X509StoreContextError:
            return False
        else:
            return True


    def verify_certificate(self, cert_pem):
        '''
        Verifies whether a provided Portuguese Citizenship Card Certificate is valid
        :param cert_pem: The to-be validated certificate
        :return: True or False
        '''
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()
        store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, ROOT_CERT))
        store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, BUNDLE_CERTS))

        # Now we add the crls to the X509 store
        crl = crypto.load_crl(crypto.FILETYPE_PEM, CRL_CERTS)
        store.add_crl(crl)

        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        # verify_certificate() returns None if certificate can be validated
        return (crypto.X509StoreContext(store, certificate).verify_certificate() == None)


    def get_pubkey_from_cert(self, cert):
        '''
        Returns the public key from a certificate
        :param cert: certificate in PEM format
        :return: the public key
        '''
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        pem = crypto.dump_publickey(crypto.FILETYPE_PEM, certificate.get_pubkey())
        return self.rsa_public_pem_to_key(pem)

################
# Symmetric cryptography functions
################

    def generate_key_symmetric(self):
        return Fernet.generate_key()

    def encrypt_with_symmetric(self, text, key):
        f = Fernet(key)
        return f.encrypt(bytes(base64.encodestring(text)))

    def decrypt_with_symmetric(self, text, key):
        f = Fernet(key)
        return base64.decodestring(f.decrypt(text))

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
            length=128,
            salt=salt,
            iterations=100000,
            backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(original_key))
        return Fernet(key)


################
# Misc functions
################

    def get_hash(self, text):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(text)
        return digest.finalize()

    def get_hmac_client_com(self, src, dst, ciphered_data, peer_sym_key):
        """

        :param src: id
        :param dst:peer_id
        :param ciphered_data:
        :param peer_sym_key:
        :return: Produces a HMAC according to RFC 2104 for 'client-com' type requests
        """
        m1 = str(peer_sym_key) + str(src) + str(dst) + str(ciphered_data)
        h1 = self.get_hash(m1)
        m2 = str(peer_sym_key) + h1
        h2 = self.get_hash(m2)
        return h2

    def verify_hmac_client_com(self, src, dst, ciphered_data, peer_sym_key, hmac_value):
        """
        :param src:
        :param dst:
        :param ciphered_data:
        :param peer_sym_key:
        :param hmac_value:
        :return:  Verifies a HMAC according to RFC 2104 for 'client-com' type requests
        """
        m1 = str(peer_sym_key) + str(src) + str(dst) + str(ciphered_data)
        h1 = self.get_hash(m1)
        m2 = str(peer_sym_key) + h1
        h2 = self.get_hash(m2)
        return  hmac_value == h2

    def get_nonce(self, length=16):
        return ''.join([str(random.SystemRandom().randint(0, 9)) for i in range(length)])

#TODO: implement key_pair rotation

class security_error:
    pass