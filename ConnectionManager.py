# encoding: utf-8
import socket
from select import *
import threading
import time
from PyQt4 import QtCore
from security import *
import base64
import json
BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
SUPPORTED_CIPHER_SUITES = ["RSA_WITH_AES_128_CBC_SHA256", "ECDHE_WITH_AES_128_CBC_SHA256", "NONE"]


class ConnectionManager(QtCore.QThread):
    def __init__(self, ip, port, gui, user):
        self.user = user
        self.cipher_suite = ""
        self.sym_key = None
        self.connect_check = None
        self.connecting_event = threading.Event()
        self.event = threading.Event()
        self.event.set()
        self.running = True
        self.sec = security()
        self.out_buffer = ""
        self.in_buffer = ""
        # TODO: change connect_state to a enum? CONNECTED, etc
        self.connect_state = 1
        self.client_connect_state = {}
        QtCore.QThread.__init__(self, parent=gui)
        self.signal = QtCore.SIGNAL("newMsg")
        self.list_signal = QtCore.SIGNAL("userList")
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
            # if we have something to write add the socket to the write list
            # ugly but works :^) // :3 // :~]
            wlist = [s for s in rlist if len(self.out_buffer)>0]
            # must have timeout or it will wait forever until we get a msg from the server
            (rl, wl, xl) = select(rlist, wlist, rlist, 1)
            data = None

            if rl:
                # handle incoming data
                try:
                    data = self.s.recv(BUFSIZE)
                except:
                    # error
                    pass
                else:
                    if len(data) > 0:
                        self.handle_requests(data)
                        #self.emit(self.signal, "teste")
            # sync
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
            # /sync
            if xl:
                pass
                # error??

    def s_connect(self):
        self.id = time.time()
        msg = self.form_json_connect(1, self.user.name, self.id , SUPPORTED_CIPHER_SUITES, "")
        self.send_message(msg)
        self.connect_state += 1
        self.connecting_event.clear()
        self.connecting_event.wait(timeout=30)
        if self.connect_state != 200:
            return False
        return True

    def disconnect_from_server(self):
        pass

    def send_message(self, text):
        # to_send = self.fern.encrypt(bytes(base64.encodestring(text)))
        self.event.wait()
        self.event.clear()
        self.out_buffer += text + "\n\n"
        self.event.set()

    def handle_requests(self, request):
        self.in_buffer += request
        reqs = self.in_buffer.split(TERMINATOR)
        self.in_buffer = reqs[-1]
        reqs = reqs[:-1]
        for req in reqs:
            try:
                print "HANDLING message from server: %r", repr(req)
                try:
                    r = json.loads(req)
                    print r
                except:
                    return

                if not isinstance(r, dict):
                    return
                if 'type' not in r:
                    continue
                if r['type'] == 'ack':
                    continue  # TODO: Ignore for now
                if 'id' in r.keys():
                    ack = {'type': 'ack', 'id': r['id']}
                    self.send_message(json.dumps(ack))
                if r['type'] == 'connect':
                    self.process_connect(r)
                elif r['type'] == 'secure':
                    self.process_secure(r)

            except Exception, e:
                print e
                print "Could not handle request"

    def process_connect(self, req):
        if req['phase'] == 2:
            if self.connect_state != 2:
                return
            if req['ciphers'] not in SUPPORTED_CIPHER_SUITES:
                msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': time.time(),
                       'ciphers': req['ciphers'], 'data': 'not supported'}
                self.send_message(json.dumps(msg))
                raise ConnectionManagerError
            # TODO: check certificate of server
            self.cipher_suite = req['ciphers']
            msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': time.time(),
                   'ciphers': self.cipher_suite, 'data': 'ok b0ss'}
            self.send_message(json.dumps(msg))
            self.connect_state += 1

        if req['phase'] == 4:
            if self.connect_state != 3:
                return
            if self.cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                if len(req['data']) == 0:
                    return
                server_pubkey = self.sec.rsa_public_pem_to_key(base64.decodestring(req['data']))
                sym_key = self.sec.generate_key_symmetric()
                self.sym_key = sym_key
                to_send = self.sec.rsa_encrypt_with_public_key(sym_key, server_pubkey)
                to_send = base64.encodestring(to_send)
                msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': time.time(),
                       'ciphers': self.cipher_suite, 'data': to_send}
                self.send_message(json.dumps(msg))
                self.connect_state += 1
                self.connect_check = self.sec.get_hash(bytes(str(msg['id']) + msg['data']))
            elif self.cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                # TODO: DH
                pass

        if req['phase'] == 6:
            if self.connect_state != 4:
                return
            if len(req['data']) == 0:
                return
            if self.cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                check = self.sec.decrypt_with_symmetric(base64.decodestring(req['data']), self.sym_key)
                if check != self.connect_check:
                    print "erro1"
                    raise ConnectionManagerError
                self.connect_state = 200
                self.connecting_event.set()
                # Connected!
            elif self.cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                # TODO: DH
                pass

    def process_secure(self, req):
        if self.connect_state != 200:
            return
        pl = self.sec.decrypt_with_symmetric(base64.decodestring(req['payload']), self.sym_key)
        plj = json.loads(pl)

        if plj['type'] == 'list':
            self.process_list(plj)
        elif plj['type'] == 'client-connect':
            self.process_client_connect(plj)
        elif plj['type'] == 'client-disconnect':
            self.process_client_disconnect(plj)
        elif plj['type'] == 'client-com':
            self.process_client_com(plj)
        elif plj['type'] == 'ack':
            self.process_client_ack(plj)

    def process_client_connect(self, ccj):
        if not ccj['type'] == 'client-connect':
            return
        if not self.connect_state == 200:
            return


        if ccj['phase'] == 1:
            if not self.client_connect_state[ccj['src']] == None:
                return

            msg = json.dumps({"type": "client-connect", "src": self.id, "dst": ccj['src'], "phase": 2, "ciphers": SUPPORTED_CIPHER_SUITES,
                              "data": "sup"})

            ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.sym_key))
            secure_msg = {'type': 'secure', 'payload': ciphered_pl}

            self.send_message(json.dumps(secure_msg))

            self.client_connect_state[ccj['dst']] = 2

        elif ccj['phase'] == 2:
            if not self.client_connect_state[ccj['src']] == 1:
                return


        elif ccj['phase'] == 3:
            if not self.client_connect_state[ccj['src']] == 2:
                return

        elif ccj['phase'] == 4:
            if not self.client_connect_state[ccj['src']] == 3:
                return

        elif ccj['phase'] == 5:
            if not self.client_connect_state[ccj['src']] == 4:
                return

        elif ccj['phase'] == 6:
            if not self.client_connect_state[ccj['src']] == 5:
                return



    def start_client_connect(self, dst):
        #TODO everything
        self.client_connect_state[dst] = 1
        pass

    def process_client_disconnect(self, cdj):
        if not cdj['type'] == 'client-disconnect':
            return
        if not self.connect_state == 200:
            return

        self.client_connect_state[cdj['src']] = None
        return


    def get_user_lists(self):
        get_list = {'type': 'list', 'data': 'passa ai os users sff'}
        get_list = self.sec.encrypt_with_symmetric(json.dumps(get_list), self.sym_key)
        msg = {'type': 'secure', 'sa-data': 'aa', 'payload': get_list}
        self.send_message(json.dumps(msg))

    def process_list(self, data):
        if 'data' not in data.keys():
            return
        user_list = data['data']
        self.emit(self.list_signal, data['data'])


    @staticmethod
    def is_ip_address(ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def form_json_connect(self, phase, name, id, ciphers, data):
        if not phase or not name or not id or not ciphers:
            return None
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
