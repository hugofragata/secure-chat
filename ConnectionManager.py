# encoding: utf-8
import socket
from select import *
import threading
import time
from PyQt4 import QtCore
from cryptography.fernet import Fernet
import base64
import json
BUFSIZE = 512 * 1024
SUPPORTED_CIPHER_SUITE = "RSA_FERNET"

class ConnectionManager(QtCore.QThread):
    def __init__(self, ip, port, gui, user):
        self.user = user
        self.event = threading.Event()
        self.event.set()
        self.running = True
        self.out_buffer = ""
        self.in_buffer = ""
        self.connect_state = 0
        QtCore.QThread.__init__(self, parent = gui)
        self.signal = QtCore.SIGNAL("newMsg")
        try:
            self.s = socket.create_connection((ip, port))
        except:
            raise ConnectionManagerError
        else:
            self.start()

    def run(self):
        while self.running:
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
                        self.handle_requests(data)
                        self.emit(self.signal, "teste")
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
        msg = self.form_json_connect(1, self.user.name, time.time(), SUPPORTED_CIPHER_SUITE, "")
        self.send_message(msg)
        self.connect_state += 1
        return True

    def disconnect_from_server(self):
        pass

    def send_message(self, text):
        #to_send = self.fern.encrypt(bytes(base64.encodestring(text)))
        self.event.wait()
        self.event.clear()
        self.out_buffer += text + "\n\n"
        self.event.set()

    def handle_requests(self, request):
        try:
            print "HANDLING message from server: %r", repr(request)

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                return  # TODO: Ignore for now

            self.send_message({'type': 'ack'})

            if req['type'] == 'connect':
                self.process_connect(req)
            elif req['type'] == 'secure':
                self.process_secure(req)

        except Exception, e:
            print "Could not handle request"

    def process_connect(self, req):
        if self.connect_state < 1:
            return


    def process_secure(self, req):
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

    def form_json_connect(self, phase, name, id, ciphers, data):
        if not phase or not name or not id or not ciphers or not data:
            raise json.error
        return json.dumps(
            {"type": "connect", "phase": int(phase), "name": name, "id": id, "ciphers": ciphers, "data": data})

    def form_json_secure(self, type, sa_data, payload):
        if not type or not sa_data or not payload:
            raise json.error
        return json.dumps({"type": "secure", "sa-data": sa_data, "payload": payload})

    def form_json_list(self, type, data):
        if not type or not data:
            raise json.error
        return json.dumps({"type": "list", "data": data})

    def form_json_client_connect(self, type, src, dst, phase, ciphers, data):
        if not type or not data:

    def form_json_client_connect(self, src, dst, phase, ciphers, data):
        if not src or not data or not dst or not phase or not ciphers or not data:
            raise json.error
        return json.dumps(
            {"type": "client-connect", "src": src, "dst": dst, "phase": phase, "ciphers": ciphers, "data": data})

    def form_json_client_disconnect(self, type, src, dst, data):

    def form_json_client_disconnect(self, src, dst, data):
        if not type or not data:
            raise json.error
        return json.dumps({"type": "client-disconnect", "src": src, "dst": dst, "data": data})

    def form_json_ack(self, type, src, dst, data):
        if not type or not data:

    def form_json_ack(self, src, dst, data):
        if not src or not data or not dst:
            raise json.error
        return json.dumps({"type": "ack", "src": src, "dst": dst, "data": data})

    def form_json_client_com(self, type, src, dst, data):
        if not type or not data:

    def form_json_client_com(self, src, dst, data):
        if not src or not data or not dst:
            raise json.error
        return json.dumps({"type": "client-com", "src": src, "dst": dst, "data": data})


class ConnectionManagerError(Exception):
    pass
