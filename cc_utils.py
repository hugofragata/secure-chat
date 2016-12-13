from OpenSSL import crypto
import PyKCS11
import base64
import os
WIN_LIB = "pteidpkcs11.dll"
ROOT_CERT = "./baltimore_root.cer"
BUNDLE_CERTS ="./cc_bundle_tree.cer"
CRL_CERTS = ''#open('./cc_bundle_tree.cer', 'r').read()


class Ccutils:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(WIN_LIB)
        self.slots = self.pkcs11.getSlotList()
        print self.slots
        self.session = self.pkcs11.openSession(self.slots[0])

    @staticmethod
    def verify_certificate(cert_pem):
        '''
        Verifies whether a provided Portuguese Citizenship Card Certificate is valid
        :param cert_pem: The to-be validated certificate
        :return: True or False
        '''
        certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_pem)

        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()
        # store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, open(ROOT_CERT, 'r').read()))
        path = "./certs/"
        print os.listdir(path)
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

    def get_info(self, label=None):
        '''
        :return: [(tuple of values),...]
        or
        :return: value of label
        '''
        cer = self.get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
        cer = crypto.load_certificate(crypto.FILETYPE_ASN1, cer)
        subj = cer.get_subject()
        if label is None:
            return subj.get_components()
        for l in subj.get_components():
            if l[0] == label:
                return l[1]

    def get_certificate(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
        '''

        :param label: the Certificate label to get
        :return: The certificate in ASN1 (DER) format
        '''
        objs = self.session.findObjects(template=((PyKCS11.CKA_LABEL, label), (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)))
        cer_bytes = objs[0].to_dict()["CKA_VALUE"]
        cer = ''.join(chr(c) for c in cer_bytes)
        return cer

    def sign_data(self, data):
        key = self.session.findObjects(template=((PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY"),
                                            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA)))[0]
        mec = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
        signed = self.session.sign(key, data, mec)
        result = base64.encodestring(''.join(chr(c) for c in signed))
        return result

#TODO: create cert from server's static key_pair