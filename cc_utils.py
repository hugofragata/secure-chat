from OpenSSL import crypto
import PyKCS11
import base64
import os
WIN_LIB = "pteidpkcs11.dll"

CRL_CERTS = ''#open('./cc_bundle_tree.cer', 'r').read()
TYPE_ASN1 = crypto.FILETYPE_ASN1
TYPE_PEM = crypto.FILETYPE_PEM


class Ccutils:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(WIN_LIB)
        self.slots = self.pkcs11.getSlotList()
        print self.slots
        self.session = self.pkcs11.openSession(self.slots[0])

    def get_info(self, label=None):
        '''
        :return: [(tuple of values),...]
        or
        :return: value of label
        '''
        cer = self.get_certificate("CITIZEN AUTHENTICATION CERTIFICATE", type=TYPE_ASN1)
        cer = crypto.load_certificate(crypto.FILETYPE_ASN1, cer)
        subj = cer.get_subject()
        if label is None:
            return subj.get_components()
        for l in subj.get_components():
            if l[0] == label:
                return l[1]

    def get_certificate(self, label="CITIZEN AUTHENTICATION CERTIFICATE", type=TYPE_PEM):
        '''

        :param label: the Certificate label to get
        :param type: the encoding of the certificate to return
        :return: The certificate in PEM format
        '''
        objs = self.session.findObjects(template=((PyKCS11.CKA_LABEL, label), (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)))
        cer_bytes = objs[0].to_dict()["CKA_VALUE"]
        cer = ''.join(chr(c) for c in cer_bytes)
        if type == TYPE_ASN1:
            return cer
        else:
            return crypto.dump_certificate(type, crypto.load_certificate(crypto.FILETYPE_ASN1, cer))

    def sign_data(self, data):
        key = self.session.findObjects(template=((PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY"),
                                            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA)))[0]
        mec = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
        signed = self.session.sign(key, data, mec)
        result = base64.encodestring(''.join(chr(c) for c in signed))
        return result