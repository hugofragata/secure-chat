# encoding: utf-8
import socket
from select import *
import threading
import time
from User import User
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
        # Dic with id:User
        self.peers = {}
        self.peer_connected = None #id of connect peer client
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
        self.user.id = time.time()
        msg = self.form_json_connect(1, self.user.name, self.user.id, SUPPORTED_CIPHER_SUITES, "")
        self.send_message(msg)
        self.user.connection_state += 1
        self.connecting_event.clear()
        self.connecting_event.wait(timeout=30)
        if self.user.connection_state != 200:
            return False
        return True

    def disconnect_from_server(self):
        if not self.user.connection_state == 200:
            return
        msg = {'type':'disconnect', 'name':self.user.name, 'src':self.user.id}
        msgs = json.dumps(msg)
        self.send_message(msgs)

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
            if self.user.connection_state != 2:
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
            self.user.connection_state += 1

        if req['phase'] == 4:
            if self.user.connection_state != 3:
                return
            if self.cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                if len(req['data']) == 0:
                    return
                server_pubkey = self.sec.rsa_public_pem_to_key(base64.decodestring(req['data']))
                sym_key = self.sec.generate_key_symmetric()
                self.sym_key = sym_key #b-b-but that's lewd, s-senpai :3
                to_send = self.sec.rsa_encrypt_with_public_key(sym_key, server_pubkey)
                to_send = base64.encodestring(to_send)
                msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': time.time(),
                       'ciphers': self.cipher_suite, 'data': to_send}
                self.send_message(json.dumps(msg))
                self.user.connection_state += 1
                self.connect_check = self.sec.get_hash(bytes(str(msg['id']) + msg['data']))
            elif self.cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                # TODO: DH
                pass

        if req['phase'] == 6:
            if self.user.connection_state != 4:
                return
            if len(req['data']) == 0:
                return
            if self.cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                check = self.sec.decrypt_with_symmetric(base64.decodestring(req['data']), self.sym_key)
                if check != self.connect_check:
                    raise ConnectionManagerError
                self.user.connection_state = 200
                self.connect_check = ""
                self.connecting_event.set()
                # Connected!
            elif self.cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                # TODO: DH
                pass

    def process_secure(self, req):
        if self.user.connection_state != 200:
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
            self.send_ack_peer(plj['data'])
        elif plj['type'] == 'ack':
            self.process_client_ack(plj)

    def send_ack_peer(self, comm_data):
        hashed_data = self.sec.get_hash(comm_data)
        dst_id = self.peers[self.peer_connected].id
        msg_to_peer = json.dumps({'type': 'ack', 'src': self.user.id, 'dst': dst_id, 'data': hashed_data})

        payload_to_server = self.sec.encrypt_with_symmetric(msg_to_peer, self.sym_key)
        msg_secure_ciphered = json.dumps({'type': 'secure', 'sa-data': 'not used', 'payload': payload_to_server})
        self.send_message(msg_secure_ciphered)

    def process_client_com(self, payload_j):
        peer_id = self.peers[self.peer_connected].id
        if not payload_j['src'] == peer_id:
            return
        if not self.user.connection_state == 200:
            return

        ciphered_data = payload_j['data']
        peer_sym_key = self.peers[self.peer_connected].sa_data

        deciphered_data = base64.decodestring(self.sec.decrypt_with_symmetric(ciphered_data, peer_sym_key))

        self.emit(self.signal, deciphered_data)

        return

    def process_client_ack(self, ack_json_from_peer):
        pass

    def send_client_comm(self, text):
        if not self.peers[self.peer_connected].connection_state == 200:
            return

        dst_sym_key = self.peers[self.peer_connected].sa_data
        dst_id = self.peer_connected
        ciphered_data_to_client = base64.encodestring(self.sec.encrypt_with_symmetric(text, dst_sym_key))
        msg_to_client = json.dumps({'type': 'client-com', 'src': self.user.id, 'dst': dst_id, 'data': ciphered_data_to_client})
        payload_to_server = self.sec.encrypt_with_symmetric(msg_to_client, self.sym_key)
        msg_secure_ciphered = json.dumps({'type': 'secure', 'sa-data': 'not used', 'payload': payload_to_server})
        self.send_message(msg_secure_ciphered)

    def process_client_connect(self, ccj):
        if self.user.connection_state != 200:
            return
        if not all(k in ccj.keys() for k in ("src", "dst", "phase", "id", "ciphers")):
            return

        if ccj['phase'] == 1:
            if ccj['src'] not in self.peers:
                self.peers[ccj['src']] = User(ccj['data'], uid=ccj['src'])
            elif self.peers[ccj['src']].connection_state != 1:
                return
            # TODO: choose suite
            msg = json.dumps({"type": "client-connect", 'id': time.time(), "src": self.user.id, "dst": ccj['src'], "phase": 2, "ciphers": ccj['ciphers'][0],
                              "data": self.user.name})
            ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.sym_key))
            secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
            self.send_message(json.dumps(secure_msg))
            self.peers[ccj['src']].connection_state = 2

        elif ccj['phase'] == 2:
            if ccj['src'] not in self.peers:
                print "unknown user"
                return
            if self.peers[ccj['src']].connection_state != 2:
                return
            if ccj['ciphers'] not in SUPPORTED_CIPHER_SUITES:
                print "unsupported cipher suite"
                # TODO: delete peer?
                msg = json.dumps({"type": "client-connect", 'id': time.time(), "src": self.user.id, "dst": ccj['src'], "phase": 3, "ciphers": ccj['ciphers'],
                              "data": "not supported"})
            else:
                msg = json.dumps({"type": "client-connect", 'id': time.time(), "src": self.user.id, "dst": ccj['src'], "phase": 3, "ciphers": ccj['ciphers'],
                              "data": "ok b0ss"})
                self.peers[ccj['src']].cipher_suite = ccj['ciphers']
            ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.sym_key))
            secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
            self.send_message(json.dumps(secure_msg))
            self.peers[ccj['src']].connection_state = 3

        elif ccj['phase'] == 3:
            if ccj['src'] not in self.peers:
                print "unknown user"
                return
            if self.peers[ccj['src']].connection_state != 2:
                return
            if ccj['data'] != "ok b0ss":
                print "cipher suite negotiation error"
                #TODO: del peer?
                return
            if ccj['ciphers'] != self.peers[ccj['src']].cipher_suite:
                print "cipher suite error"
                return
            if self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                priv_key, pub_key = self.sec.rsa_gen_key_pair()
                self.peers[ccj['src']].sa_data = priv_key
                priv_key = ""
                msg = json.dumps(
                    {"type": "client-connect", 'id': time.time(), "src": self.user.id, "dst": ccj['src'], "phase": 4,
                     "ciphers": ccj['ciphers'],
                     "data": base64.encodestring(self.sec.rsa_public_key_to_pem(pub_key))})
                ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.sym_key))
                secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
                self.send_message(json.dumps(secure_msg))
                self.peers[ccj['src']].connection_state = 3
            elif ccj['ciphers'] == SUPPORTED_CIPHER_SUITES[1]:
                #TODO:DH
                pass

        elif ccj['phase'] == 4:
            if ccj['src'] not in self.peers:
                print "unknown user"
                return
            if self.peers[ccj['src']].connection_state != 3:
                return
            if ccj['ciphers'] != self.peers[ccj['src']].cipher_suite:
                print "cipher suite error"
                return
            if self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                user_pubkey = self.sec.rsa_public_pem_to_key(base64.decodestring(ccj['data']))
                self.peers[ccj['src']].sa_data = self.sec.generate_key_symmetric()
                to_send = self.sec.rsa_encrypt_with_public_key(self.peers[ccj['src']].sa_data, user_pubkey)
                to_send = base64.encodestring(to_send)
                msg = json.dumps(
                    {"type": "client-connect", 'id': time.time(), "src": self.user.id, "dst": ccj['src'], "phase": 5,
                     "ciphers": ccj['ciphers'],
                     "data": to_send})
                ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.sym_key))
                secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
                self.send_message(json.dumps(secure_msg))
                self.peers[ccj['src']].connection_state = 4
                self.peers[ccj['src']].conn_check = self.sec.get_hash(bytes(str(msg['id']) + msg['data']))
            elif self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                #TODO: DH
                pass

        elif ccj['phase'] == 5:
            if ccj['src'] not in self.peers:
                print "unknown user"
                return
            if self.peers[ccj['src']].connection_state != 3:
                return
            if ccj['ciphers'] != self.peers[ccj['src']].cipher_suite:
                print "cipher suite error"
                return
            if self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                self.peers[ccj['src']].sa_data = self.sec.rsa_decrypt_with_private_key(base64.decodestring(ccj['data']), self.peers[ccj['src']].sa_data)
                to_send = self.sec.encrypt_with_symmetric(
                    self.sec.get_hash(bytes(str(ccj['id']) + ccj['data'])), self.peers[ccj['src']].sa_data)
                to_send = base64.encodestring(to_send)
                msg = json.dumps(
                    {"type": "client-connect", 'id': time.time(), "src": self.user.id, "dst": ccj['src'], "phase": 6,
                     "ciphers": ccj['ciphers'],
                     "data": to_send})
                ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.sym_key))
                secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
                self.send_message(json.dumps(secure_msg))
                self.peers[ccj['src']].connection_state = 4
            elif self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                # TODO: DH
                pass

        elif ccj['phase'] == 6:
            if ccj['src'] not in self.peers:
                print "unknown user"
                return
            if self.peers[ccj['src']].connection_state != 3:
                return
            if ccj['ciphers'] != self.peers[ccj['src']].cipher_suite:
                print "cipher suite error"
                return
            if self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                check = self.sec.decrypt_with_symmetric(base64.decodestring(ccj['data']), self.peers[ccj['src']].sa_data)
                if check != self.peers[ccj['src']].conn_check:
                    print "client comm shared secret error"
                    raise ConnectionManagerError
                self.peers[ccj['src']].connection_state = 200
                self.peers[ccj['src']].conn_check = None
                self.peer_connected = ccj['src']
            elif self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                # TODO: DH
                pass

    def start_client_connect(self, dst):
        if dst == self.peer_connected:
            return
        if self.peers[dst].connection_state == 200:
            self.peer_connected = dst
            return
        else:
            msg = json.dumps(
                {"type": "client-connect", 'id': time.time(), "src": self.user.id, "dst": dst, "phase": 1,
                 "ciphers": SUPPORTED_CIPHER_SUITES,
                 "data": self.user.name})
            ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.sym_key))
            secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
            self.send_message(json.dumps(secure_msg))
            self.peers[dst].connection_state = 2
        pass

    def process_client_disconnect(self, cdj):
        if not cdj['type'] == 'client-disconnect':
            return
        if not self.user.connection_state == 200:
            return
        if not self.peer_connected == cdj['src']:
            return

        del self.peers[self.peer_connected]
        self.peer_connected = None
        return

    def get_user_lists(self):
        get_list = {'type': 'list', 'data': 'passa ai os users sff'}
        get_list = self.sec.encrypt_with_symmetric(json.dumps(get_list), self.sym_key)
        msg = {'type': 'secure', 'sa-data': 'aa', 'payload': get_list}
        self.send_message(json.dumps(msg))

    def process_list(self, data):
        if 'data' not in data.keys():
            return
        for u in data['data']:
            self.peers[u['id']] = User(u['name'], uid=u['id'])
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
