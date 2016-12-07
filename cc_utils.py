from OpenSSL import crypto

ROOT_CERT = open('./baltimore_root.cer', 'r').read()
BUNDLE_CERTS = open('./cc_bundle_tree.cer', 'r').read()
CRL_CERTS = open('./cc_bundle_tree.cer', 'r').read()

def verify_certificate(cert_pem):
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

def get_info(cert_pem):
    '''
    :param cert_pem: Certificate to extract info
    :return: [commonName, (tuple of values)]
    '''
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    subj = cert.get_subject()
    return subj.get_components()

#TODO: create cert from server's static key_pair