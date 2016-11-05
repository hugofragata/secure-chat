

class User:

    def __init__(self, name):
        self.name = name
        self.id = None
        self.sa_data = None
        self.connection_state = 0

    def send(self, text):
        pass

