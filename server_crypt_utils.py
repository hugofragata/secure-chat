from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import utils
import os
import base64
import datetime


def get_certificate():
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
            password = 'nsaplsnospythanks',
            backend = default_backend()
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
            password = 'nsaplsnospythanks',
            backend = default_backend()
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
