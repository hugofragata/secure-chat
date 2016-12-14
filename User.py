import time

class User:
    def __init__(self, name, uid=None):
        self.name = name
        if uid is None:
            self.id = time.time()
        else:
            self.id = uid
        self.sa_data = None # sym_key to use with peered client
        self.connection_state = 1
        self.cipher_suite = None
        self.conn_check = None
        self.buffin = ""
        self.waiting_acks = []


class SuperUser(User):
    def __init__(self, name=None, ccutils=None):
        User.__init__(self, name)
        if ccutils is None and (name is None):
            raise UserError
        if ccutils is not None:
            self.cc = ccutils
            self.ccauth = True
            self.name = self.cc.get_info('CN')
            self.id = self.cc.get_info("serialNumber")
        else:
            self.cc = None
            self.ccauth = False
            self.name = name
            self.id = time.time()
        self.pub_key = None
        self.priv_key = None

    def sign(self, data):
        return self.cc.sign_data(data)

    def get_certificate(self):
        '''

        :return: the user CITIZEN AUTHENTICATION KEY certificate
        '''
        return self.cc.get_certificate()

class UserError(Exception):
    pass