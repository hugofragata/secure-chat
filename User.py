

class User:

    def __init__(self, name, uid=None):
        self.name = name
        self.id = uid
        self.sa_data = None #sym_key to use with peered client
        self.connection_state = 1

