# encoding: utf-8
import socket
from select import *
import thread
import json
import random
from PyQt4 import QtCore
BUFSIZE = 512 * 1024


class ConnectionManager(QtCore.QThread):
    def __init__(self, ip, port, gui):
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
                        self.emit(self.signal, data)

            if wl:
                try:
                    sent = self.s.send(self.out_buffer[:BUFSIZE])
                    self.out_buffer = self.out_buffer[sent:]  # leave remaining to be sent later
                except:
                    pass
            if xl:
                pass
                #error??

    def s_connect(self):
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

    def form_json(self, type, src=None, dst=None, data=None,name=None, phase=None, ciphers=None, sa_data=None, id=None, payload=None):
        j = None
        try:
            if type=="connect":
                j = json.dumps({"type":type, "phase":int(phase), "name":name, "id":id, "ciphers":ciphers, "data":data })

            elif type=="secure":
                j = json.dumps({"type": type, "sa-data": sa_data, "payload": payload})

            elif type == "list":
                j = json.dumps({"type": type, "data":data})

            elif type == "client-connect":
                j = json.dumps({"type": type, "src":src,  "dst":dst, "phase":phase, "ciphers":ciphers, "data": data})

            elif type == "client-disconnect" or type == "ack" or type=="client-com":
                j = json.dumps({"type": type, "src": src, "dst": dst, "data": data})
        except:
            raise ConnectionManagerError
        return j

    def form_json_connect(self, type, phase, name, id, ciphers, data):
        if not type or not phase or not name or not id or not ciphers or not data:
            raise json.error
        return json.dumps({"type": "connect", "phase": int(phase), "name": name, "id": id, "ciphers": ciphers, "data": data})


    def form_json_secure(self, type, sa_data, payload):
        if not type or not sa_data or not payload:
            raise json.error
        return json.dumps({"type": "secure", "sa-data": sa_data, "payload": payload})


    def form_json_list(self, type, data):
        if not type or not data:
            raise json.error
        return json.dumps({"type": "list", "data":data})


    def form_json_client_connect(self, type, src, dst, phase, ciphers, data):
        if not type or not data:
            raise json.error
        return json.dumps({"type": "client-connect", "src":src,  "dst":dst, "phase":phase, "ciphers":ciphers, "data": data})


    def form_json_client_disconnect(self, type, src, dst, data):
        if not type or not data:
            raise json.error
        return json.dumps({"type": "client-disconnect", "src": src, "dst": dst, "data": data})


    def form_json_ack(self, type, src, dst, data):
        if not type or not data:
            raise json.error
        return json.dumps({"type": "ack", "src": src, "dst": dst, "data": data})

    def form_json_client_com(self, type, src, dst, data):
        if not type or not data:
            raise json.error
        return json.dumps({"type": "client-com", "src": src, "dst": dst, "data": data})

class ConnectionManagerError(Exception):
    pass