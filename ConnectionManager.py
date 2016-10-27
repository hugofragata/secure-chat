# encoding: utf-8
import socket
from select import *
import threading
from PyQt4 import QtCore
import cryptography
from cryptography.fernet import Fernet
import os.path
import base64
BUFSIZE = 512 * 1024


class ConnectionManager(QtCore.QThread):
    def __init__(self, ip, port, gui):
        self.event = threading.Event()
        self.event.set()
        self.gui = gui
        self.out_buffer = ""
        self.in_buffer = ""
        if os.path.isfile("teste.txt"):
            with open("teste.txt", "r") as f:
                key = f.read()
                self.fern = Fernet(bytes(key))
                del key
        else:
            key = Fernet.generate_key()
            with open("teste.txt", 'w') as f:
                f.write(key)
            self.fern = Fernet(key)
            del key

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
                        print data
                        clear_msg = self.fern.decrypt(bytes(data))
                        clear_msg = base64.decodestring(clear_msg)
                        print "clear text"
                        print clear_msg
                        self.emit(self.signal, clear_msg)

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
        #to_send = self.fern.encrypt(bytes(base64.encodestring(text)))
        to_send = self.fern.encrypt(bytes(base64.encodestring(text)))

        self.event.wait()
        self.event.clear()
        self.out_buffer += to_send + "\n\n"
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


    def form_json(self, type, src=None, dst=None, data=None, name=None, phase=None, ciphers=None, sa_data=None, id=None,
                  payload=None):
        j = None
        try:
            if type == "connect":
                j = json.dumps(
                    {"type": type, "phase": int(phase), "name": name, "id": id, "ciphers": ciphers, "data": data})

            elif type == "secure":
                j = json.dumps({"type": type, "sa-data": sa_data, "payload": payload})

            elif type == "list":
                j = json.dumps({"type": type, "data": data})

            elif type == "client-connect":
                j = json.dumps({"type": type, "src": src, "dst": dst, "phase": phase, "ciphers": ciphers, "data": data})

            elif type == "client-disconnect" or type == "ack" or type == "client-com":
                j = json.dumps({"type": type, "src": src, "dst": dst, "data": data})
        except:
            raise ConnectionManagerError
        return j


    def form_json_connect(self, phase, name, id, ciphers, data):
        if not phase or not name or not id or not ciphers or not data:
            raise json.error
        return json.dumps(
            {"type": "connect", "phase": int(phase), "name": name, "id": id, "ciphers": ciphers, "data": data})


    def form_json_secure(self, sa_data, payload):
        if not  sa_data or not payload:
            raise json.error
        return json.dumps({"type": "secure", "sa-data": sa_data, "payload": payload})


    def form_json_list(self, data):
        if not data:
            raise json.error
        return json.dumps({"type": "list", "data": data})


    def form_json_client_connect(self, src, dst, phase, ciphers, data):
        if not src or not data or not dst or not phase or not ciphers or not data:
            raise json.error
        return json.dumps(
            {"type": "client-connect", "src": src, "dst": dst, "phase": phase, "ciphers": ciphers, "data": data})


    def form_json_client_disconnect(self, src, dst, data):
        if not type or not data:
            raise json.error
        return json.dumps({"type": "client-disconnect", "src": src, "dst": dst, "data": data})


    def form_json_ack(self, src, dst, data):
        if not src or not data or not dst:
            raise json.error
        return json.dumps({"type": "ack", "src": src, "dst": dst, "data": data})


    def form_json_client_com(self, src, dst, data):
        if not src or not data or not dst:
            raise json.error
        return json.dumps({"type": "client-com", "src": src, "dst": dst, "data": data})


class ConnectionManagerError(Exception):
    pass
