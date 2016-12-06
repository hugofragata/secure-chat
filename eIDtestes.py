import PyKCS11


lib = "pteidpkcs11.dll"
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()
session = pkcs11.openSession(slots[0])
objs = session.findObjects(template=())
print session.PTEID_GetCertificates()
for obj in objs:
    print "---------------------------------------------------"
    print type(obj)
    print "---------------------------------------------------"
    print obj

#a = session.findObjects(template=(PyKCS11.LowLevel.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"))
#(PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"),                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)