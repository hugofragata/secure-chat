
from User import User
from cc_utils import Ccutils
from PyQt4 import QtGui
class TesteCC:
    def __init__(self):
        self.teste=User(ccutils=Ccutils())
        print self.teste.name

ola = TesteCC()

'''
from cc_utils import Ccutils
teste = Ccutils()
print teste.get_info("serialNumber")
'''

'''
lib = "pteidpkcs11.dll"
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()
session = pkcs11.openSession(slots[0])
objs = session.findObjects(template=((PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"), (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)))
#print session.PTEID_GetCertificates()
cer = None
for obj in objs:
    print "---------------------------------------------------"
    print type(obj)
    print "---------------------------------------------------"
    cer = obj.to_dict()["CKA_VALUE"]

der = ''.join(chr(c) for c in cer)
cer = x509.load_der_x509_certificate(der, default_backend())

for atr in cer.subject:
    print atr
print cer

#(PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"),                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)
'''