import socket


class ConnectionManager:
    def __init__(self, ip, port):
        #self.ip = ip
        #self.port = port
        #self.s = socket.socket(
        #    socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s = socket.create_connection((ip, port))
        except:
            raise socket.error

    def connect(self):
        #TODO: inform server of who we are and prove it
        return True

    def disconnect_from_server(self):
        pass

    def send_message(self, text):
        total_sent = 0

        #TODO: format text to comply with server's protocol
        #TODO: call User module and cipher text

        while total_sent < len(text):
            sent = self.s.send(text[total_sent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            total_sent = total_sent + sent


    def get_messages(self, user):
        pass

    def get_user_lists(self):
        pass

    def verify_ack_received(self, msg_id):
        pass

    def verify_ack_read(self, msg_id):
        pass

    def send_ack_msg_received(self, msg_id):
        pass

    def send_ack_msg_read(self, msg_id):
        pass

    @staticmethod
    def is_ip_address(ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False


class ConnectionManagerError(Exception):
    pass
