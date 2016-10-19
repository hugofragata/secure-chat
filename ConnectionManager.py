import socket
from select import *
import thread

BUFSIZE = 512 * 1024


class ConnectionManager:
    def __init__(self, ip, port, gui):
        self.gui = gui
        self.out_buffer = ""
        self.in_buffer = ""
        try:
            self.s = socket.create_connection((ip, port))
        except:
            raise ConnectionManagerError
        else:
            thread.start_new_thread(self.main_loop, ())


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
    def main_loop(self):
        while True:
            # we only have one socket to read from
            rlist = [self.s]
            #if we have something to write add the socket to the write list
            #ugly but works :^)
            wlist = [s for s in rlist if len(self.out_buffer) > 0]
            #wait
            (rl, wl, xl) = select(rlist, wlist, rlist)
            data = None
            if rl:
                #handle incoming data
                try:
                    data = self.s.recv(BUFSIZE)
                except:
                    #error
                    pass
                else:
                    if len(data) > 0:
                        #must send signal to gui this way doesn't work
                        #JUST
                        self.gui.updateChat(data)

            if wl:
                try:
                    sent = self.s.send(self.out_buffer[:BUFSIZE])
                    self.out_buffer = self.out_buffer[sent:]  # leave remaining to be sent later
                except:
                    pass
            if xl:
                pass
                #error??



    @staticmethod
    def is_ip_address(ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False


class ConnectionManagerError(Exception):
    pass
