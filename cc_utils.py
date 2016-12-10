from OpenSSL import crypto
import PyKCS11
WIN_LIB = "pteidpkcs11.dll"
ROOT_CERT = open('./baltimore_root.cer', 'r').read()
BUNDLE_CERTS = open('./cc_bundle_tree.cer', 'r').read()
CRL_CERTS = ''#open('./cc_bundle_tree.cer', 'r').read()


class Ccutils:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(WIN_LIB)
        self.slots = self.pkcs11.getSlotList()
        print self.slots
        self.session = self.pkcs11.openSession(self.slots[0])

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

    def get_info(self, label=None):
        '''
        :return: [(tuple of values),...]
        or
        :return: value of label
        '''
        cer = self.get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
        subj = cer.get_subject()
        if label is None:
            return subj.get_components()
        for l in subj.get_components():
            if l[0] == label:
                return l[1]

    def get_certificate(self, label):
        objs = self.session.findObjects(template=((PyKCS11.CKA_LABEL, label), (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)))
        cer_bytes = objs[0].to_dict()["CKA_VALUE"]
        cer = ''.join(chr(c) for c in cer_bytes)
        return crypto.load_certificate(crypto.FILETYPE_ASN1, cer)
#TODO: create cert from server's static key_pair