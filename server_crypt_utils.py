from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import utils
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from OpenSSL import crypto
import os
import random
import base64
import datetime

PADDING_PSS = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH)
PADDING_PKCS1 = padding.PKCS1v15()
SHA2 = hashes.SHA256()
SHA1 = hashes.SHA1()


def get_certificate():
    '''
    Create a self signed certificate with the server private key
    :return: Certificate PEM encoded
    '''
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"AV"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Deti"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Sec"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"secureChat"),
    ])
    with open("key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password='nsaplsnospythanks',
            backend=default_backend()
        )
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        utils.int_from_bytes(os.urandom(20), "big") >> 1  # to support older versions of cryptography
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical = False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    del private_key
    return cert.public_bytes(serialization.Encoding.PEM)


def sign_data(data):
    '''

    :param data: data to be signed
     :type data: string
    :return: base64 encoded signature
    '''
    with open("key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password='nsaplsnospythanks',
            backend=default_backend()
        )
    signer = private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    message = str(data)
    signer.update(message)
    signature = signer.finalize()
    return base64.encodestring(signature)


def rsa_gen_key_pair():
    '''
    Generate a private, public key pair (the public key will be PEM encoded)
    :return: (private_key, public_key)
    '''
    priv_key = rsa.generate_private_key(65537, 4096, default_backend())
    pub_key = base64.encodestring(rsa_public_key_to_pem(priv_key.public_key()))
    return (priv_key, pub_key)


def rsa_public_key_to_pem(public_key):
    '''
    Pem encode a public key
    :param public_key: a public key
    :return: a pem encoded public key
    '''
    pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem


def ecdh_gen_key_pair():
    '''
    Generate the public and private keys for ECDH (the public key will be PEM encoded)
    :return: (privateKey, publicKey)
    '''
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    peer_public_key = base64.encodestring(rsa_public_key_to_pem(private_key.public_key()))
    return (private_key, peer_public_key)


def ecdh_get_shared_secret(private_key, partner_public_key):
    '''
    Derive the session key from the parner public key
    :param private_key:
    :param partner_public_key:
    :return: The session key
    '''
    shared_key = private_key.exchange(ec.ECDH(), partner_public_key)
    shared_key = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=None,
        backend=default_backend()
    ).derive(shared_key)
    return base64.urlsafe_b64encode(shared_key)


def verify_certificate(cert_pem):
    '''
    Verifies whether a provided Portuguese Citizenship Card Certificate is valid
    :param cert_pem: The to-be validated certificate
    :return: True or False
    '''
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    # Create and fill a X509Sore with trusted certs
    store = crypto.X509Store()
    path = "./certs_dev/"
    for c in os.listdir(path):
        pem = open(path + c, 'r').read()
        store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, pem))

    # Now we add the crls to the X509 store
    #crl = crypto.load_crl(crypto.FILETYPE_PEM, CRL_CERTS)
    #store.add_crl(crl)
    context = crypto.X509StoreContext(store, certificate)
    context.set_store(store)
    # Create a X590StoreContext with the cert and trusted certs
    # and verify the the chain of trust
    # verify_certificate() returns None if certificate can be validated
    valid = False
    try:
        valid = context.verify_certificate()
    except crypto.X509StoreContextError as e:
        print e.message
        print e.certificate.get_subject()
    else:
        valid = True
    return valid


def get_pubkey_from_cert(cert, type="PEM"):
    '''
    Returns the public key from a certificate
    :param type: The encoding of the certificate "PEM" or "ASN1"
    :param cert: certificate in PEM format
    :return: the public key
    '''
    certificate = None
    if type == "ASN1":
        certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
    elif type == "PEM":
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    pem = crypto.dump_publickey(crypto.FILETYPE_PEM, certificate.get_pubkey())
    return rsa_public_pem_to_key(pem)


def rsa_verify_with_public_key(signature, message, public_key, pad=PADDING_PSS, hash_alg=SHA2):
    '''
    :param signature: base64 encoded signature of the message
    :param message: plain text signed message
    :param public_key: the public key that will be used to verify
    :type public_key: RSAPublicKey
    :param pad: Padding algorithm to be used
    :param hash_alg: Hash algorithm to be used
    :return: True case valid or False case invalid
    '''
    if not signature or not public_key:
        return
    if not isinstance(public_key, rsa.RSAPublicKey):
        return
    signature = str(base64.decodestring(signature))
    mes = str(unicode(message))
    verifier = public_key.verifier(
        signature,
        pad,
        hash_alg)
    verifier.update(mes)
    try:
        verifier.verify()
    except:
        return False
    else:
        return True


def rsa_public_pem_to_key(pem):
    '''

    :param pem: the PEM encoded key
    :return: The public key object
    '''
    public_key = serialization.load_pem_public_key(
        pem,
        backend=default_backend())
    return public_key


def rsa_decrypt_with_private_key(text, private_key):
    tmp = base64.decodestring(text)
    plain_text = private_key.decrypt(tmp,
                                     padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None))
    return plain_text


def encrypt_with_symmetric(text, key):
    f = Fernet(key)
    return f.encrypt(bytes(base64.encodestring(text)))


def decrypt_with_symmetric(text, key):
    f = Fernet(key)
    return base64.decodestring(f.decrypt(text))


def get_hash(text):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(text)
    return digest.finalize()


def get_nonce(length=16):
    return ''.join([str(random.SystemRandom().randint(0, 9)) for i in range(length)])


def get_info_from_cert(cert, label=None):
    '''
    Get information from the certificate
    :param cert: the certificate in PEM
    :param label:
    :return:
    '''
    cer = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    subj = cer.get_subject()
    if label is None:
        return subj.get_components()
    for l in subj.get_components():
        if l[0] == label:
            return l[1]
