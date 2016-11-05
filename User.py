

class User:

    def __init__(self, name, uid=None):
        self.name = name
        self.id = uid
        self.sa_data = None
        self.connection_state = 1

