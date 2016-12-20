import security
s = security.security()

cert = open('certs/ECRaizEstado.crt', 'r').read()
s.get_name_from_cert(cert)