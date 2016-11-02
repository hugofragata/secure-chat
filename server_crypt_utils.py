from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime


def get_certificate():
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"AV"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Deti"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Sec"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"secureChat"),
    ])
    with open("path/to/key.pem", "rb") as key_file:
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
        x509.random_serial_number()
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

