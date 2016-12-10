import time
class User:
    def __init__(self, name=None, uid=None, ccutils=None):
        if ccutils is None and (name is None):
            raise UserError
        if ccutils is not None:
            self.cc = ccutils
            self.ccauth = True
            self.init_CC()
        else:
            self.cc = None
            self.ccauth = False
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

    def init_CC(self):
        self.name = self.cc.get_info('CN')
        self.id = self.cc.get_info("serialNumber")


class UserError(Exception):
    pass