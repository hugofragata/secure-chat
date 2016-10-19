# encoding: utf-8
import socket
from select import *
import threading
from PyQt4 import QtCore
BUFSIZE = 512 * 1024


class ConnectionManager(QtCore.QThread):
    def __init__(self, ip, port, gui):
        self.event = threading.Event()
        self.event.set()
        self.gui = gui
        self.out_buffer = ""
        self.in_buffer = ""
        QtCore.QThread.__init__(self, parent = self.gui)
        self.signal = QtCore.SIGNAL("newMsg")
        try:
            self.s = socket.create_connection((ip, port))
        except:
            raise ConnectionManagerError
        else:
            self.start()

    def run(self):
        while True:
            # we only have one socket to read from
            rlist = [self.s]
            #if we have something to write add the socket to the write list
            #ugly but works :^)
            wlist = [s for s in rlist if len(self.out_buffer)>0]
            #must have timeout or it will wait forever until we get a msg from the server
            (rl, wl, xl) = select(rlist, wlist, rlist, 1)
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
                        self.emit(self.signal, data)

            #sync
            if wl and len(self.out_buffer) > 0:
                try:
                    self.event.wait()
                    self.event.clear()
                    sent = self.s.send(self.out_buffer[:BUFSIZE])
                    self.out_buffer = self.out_buffer[sent:]  # leave remaining to be sent later
                except:
                    pass
                finally:
                    self.event.set()
            #/sync

            if xl:
                pass
                #error??

    def s_connect(self):
        #TODO: inform server of who we are and prove it
        return True

    def disconnect_from_server(self):
        pass

    def send_message(self, text):
        self.event.wait()
        self.event.clear()
        self.out_buffer += text
        self.event.set()
        """"
        total_sent = 0

        #TODO: format text to comply with server's protocol
        #TODO: call User module and cipher text

        while total_sent < len(text):
            sent = self.s.send(text[total_sent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            total_sent = total_sent + sent
        """


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
