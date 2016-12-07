import PyKCS11
from cryptography import x509
from cryptography.hazmat.backends import default_backend

lib = "pteidpkcs11.dll"
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()
session = pkcs11.openSession(slots[0])
objs = session.findObjects(template=((PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"),(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)))
#print session.PTEID_GetCertificates()
cer = None
for obj in objs:
    print "---------------------------------------------------"
    print type(obj)
    print "---------------------------------------------------"
    cer = obj.to_dict()["CKA_VALUE"]

der = ''.join(chr(c) for c in cer)
cer = x509.load_der_x509_certificate(der, default_backend())
print cer

#(PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"),                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)