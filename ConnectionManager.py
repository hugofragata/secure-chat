# encoding: utf-8
import socket
from select import *
import threading
from User import User, SuperUser
from PyQt4 import QtCore
from security import *
import base64
from cryptography.fernet import InvalidToken
import json
BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
SUPPORTED_CIPHER_SUITES = ["RSA_WITH_AES_128_CBC_SHA256", "ECDHE_WITH_AES_128_CBC_SHA256", "NONE"]

# TODO: part2
# TODO: autenticacao do servidor --> almost done
# TODO: autenticacao dos users com cartao de cidadao
# TODO: suportar mais cipher suites



class ConnectionManager(QtCore.QThread):
    def __init__(self, ip, port, gui, user):
        """
        :param ip:   the ip address of the server
        :param port: tcp port
        :param gui:
        :param user: all info about this user
        :type user: SuperUser
        """
        # User stuff
        self.user = user
        self.user.sa_data = None
        self.user.cipher_suite = ""
        # TODO: change connect_state to a enum? CONNECTED, etc
        self.connect_check = None
        self.server_pubkey = None
        # threading events
        self.connecting_event = threading.Event()
        self.event = threading.Event()
        self.event.set()

        self.running = True
        self.sec = security()
        self.out_buffer = ""
        self.in_buffer = ""

        #peers
        # Dic with id:User
        self.peers = {}
        self.peer_connected = None #id of connect peer client
        # QT signals
        QtCore.QThread.__init__(self, parent=gui)
        self.signal = QtCore.SIGNAL("newMsg")
        self.list_signal = QtCore.SIGNAL("userList")
        self.error_signal = QtCore.SIGNAL("errorSig")
        self.change_list = QtCore.SIGNAL("changeList")
        self.append_msg_id = QtCore.SIGNAL("append_msg_id")
        self.append_self_msg = QtCore.SIGNAL("append_self_msg")
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

    def s_connect(self, cipher_suite=1):
        # cipher_suite
        # if 1: "RSA_WITH_AES_128_CBC_SHA256"
        # if 2: "ECDHE_WITH_AES_128_CBC_SHA256"
        #if not self.user.ccauth:
        #    self.user.id = time.time()
        if cipher_suite == 1:
            msg = self.form_json_connect(1, self.user.name, self.user.id,
                                         [SUPPORTED_CIPHER_SUITES[0], SUPPORTED_CIPHER_SUITES[1], SUPPORTED_CIPHER_SUITES[2]], "")
        elif cipher_suite == 2:
            msg = self.form_json_connect(1, self.user.name, self.user.id,
                                         [SUPPORTED_CIPHER_SUITES[1], SUPPORTED_CIPHER_SUITES[0], SUPPORTED_CIPHER_SUITES[2]], "")
        else:
            # shouldnt happen
            return
        self.user.sa_data = msg
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
        self.user.connection_state = 1
        del self.peers
        self.peers = {}
        self.peer_connected = None
        self.send_message(msgs)

    def send_message(self, text):
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
            if len(req['data']) <= 0:
                print "ERROR connecting to server: NO CERTIFICATE"
                return
            cert = base64.decodestring(req['data'])
            if not self.sec.verify_self_signed_cert(cert):
                print "ERROR connecting to server: INVALID CERTIFICATE"
                return
            print "CERTIFICATE VALID\n\n\n\n\n\n"
            self.server_pubkey = self.sec.get_pubkey_from_cert(cert)
            if not self.sec.rsa_verify_with_public_key(req['sign'], self.user.sa_data, self.server_pubkey):
                print "ERROR wrong signature\n\n\n\n\n"
                return

            if req['ciphers'] not in SUPPORTED_CIPHER_SUITES:
                print "ERROR connecting to server"
                msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': self.sec.get_nonce(),
                       'ciphers': req['ciphers'], 'data': 'not supported'}
                self.send_message(json.dumps(msg))
                return
            self.user.cipher_suite = req['ciphers']
            if self.user.ccauth:
                self.user.priv_key, self.user.pub_key = self.sec.rsa_gen_key_pair()
                pubkey_pem = self.sec.rsa_public_key_to_pem(self.user.pub_key)
                data = {'cert': self.user.get_certificate(), 'key_sign': self.user.sign(pubkey_pem), 'key': pubkey_pem}
                msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': self.sec.get_nonce(),
                       'ciphers': self.user.cipher_suite, 'data': json.dumps(data)}
            else:
                msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': self.sec.get_nonce(),
                       'ciphers': self.user.cipher_suite, 'data': 'ok b0ss'}
            self.send_message(json.dumps(msg))
            self.user.connection_state += 1

        if req['phase'] == 4:
            if self.user.connection_state != 3:
                return
            if len(req['data']) == 0 or len(req['sign']) == 0:
                return
            if not self.sec.rsa_verify_with_public_key(req['sign'], req['id']+req['ciphers']+req['data'], self.server_pubkey):
                print "ERROR in server msg"
                return
            if self.user.cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                server_pubkey = self.sec.rsa_public_pem_to_key(base64.decodestring(req['data']))
                self.user.sa_data = self.sec.generate_key_symmetric()
                to_send = self.sec.rsa_encrypt_with_public_key(self.user.sa_data, server_pubkey)
                to_send = base64.encodestring(to_send)
                msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': self.sec.get_nonce(),
                       'ciphers': self.user.cipher_suite, 'data': to_send}
                self.connect_check = self.sec.get_hash(bytes(str(msg['id']) + msg['data']))
            elif self.user.cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                priv_key, pub_key = self.sec.ecdh_gen_key_pair()
                msg = {'type': 'connect', 'phase': req['phase'] + 1, 'name': self.user.name, 'id': self.sec.get_nonce(),
                       'ciphers': self.user.cipher_suite,
                       'data': self.sec.rsa_public_key_to_pem(pub_key)}
                peer_key = self.sec.rsa_public_pem_to_key(base64.decodestring(req['data']))
                self.user.sa_data = self.sec.ecdh_get_shared_secret(priv_key, peer_key)
                del priv_key
            else:
                return
            if self.user.ccauth:
                msg['sign'] = self.sec.rsa_sign_with_private_key(msg['id'] + msg['ciphers'] + msg['data'], self.user.priv_key)
            self.send_message(json.dumps(msg))
            self.user.connection_state += 1

        if req['phase'] == 6:
            if self.user.connection_state != 4:
                return
            if len(req['data']) == 0 or len(req['sign']) == 0:
                return
            if not self.sec.rsa_verify_with_public_key(req['sign'], req['id']+req['ciphers']+req['data'], self.server_pubkey):
                print "ERROR in server msg"
                return
            if self.user.cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                check = self.sec.decrypt_with_symmetric(base64.decodestring(req['data']), self.user.sa_data)
                if check != self.connect_check:
                    return
                del self.connect_check
                # Connected!
            elif self.user.cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                if req['data'] != "ok ecdh done":
                    return
            self.user.connection_state = 200
            self.connecting_event.set()

    def process_secure(self, req):
        if self.user.connection_state != 200:
            return
        try:
            pl = self.sec.decrypt_with_symmetric(base64.decodestring(req['payload']), self.user.sa_data)
        except InvalidToken:
            print "decrypting error\n\n"
            return
        plj = json.loads(pl)
        #if not self.sec.rsa_verify_with_public_key(plj['sign'], plj['data'], self.server_pubkey):
        #    print "Message not from server\n\n\n"
        #    return
        #plj = json.loads(plj['data'])

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

    def process_client_com(self, payload_j):
        if not self.user.connection_state == 200:
            # user is not connected so ignore this message
            return
        if self.peer_connected != payload_j['src']:
            if payload_j['src'] not in self.peers.keys():
                # no info on this peer
                return
            if self.peers[payload_j['src']].connection_state != 200:
                # i am not connected to this peer
                return
            ciphered_data = payload_j['data']
            peer_sym_key = self.peers[payload_j['src']].sa_data
            try:
                deciphered_data = self.sec.decrypt_with_symmetric(base64.decodestring(ciphered_data), peer_sym_key)
            except InvalidToken:
                self.emit(self.error_signal, "Invalid signature in " + self.peers[payload_j['src']].name + " msg!")
                return
            self.peers[payload_j['src']].buffin += deciphered_data + "\n\n"
            self.emit(self.change_list, payload_j['src'])
            self.send_client_ack(payload_j['src'], payload_j['id'])
            return
        if self.peer_connected is None:
            return
        if self.peers[self.peer_connected].connection_state != 200:
            # should never happen
            if self.peer_connected in self.peers.keys():
                del self.peers[self.peer_connected]
                self.send_client_disconnect(self.peer_connected)
                self.peer_connected = None
            return
        ciphered_data = payload_j['data']
        peer_sym_key = self.peers[self.peer_connected].sa_data
        try:
            deciphered_data = self.sec.decrypt_with_symmetric(base64.decodestring(ciphered_data), peer_sym_key)
        except InvalidToken:
            self.emit(self.error_signal, "Invalid signature in peer msg!")
            return
        self.emit(self.signal, deciphered_data)
        self.send_client_ack(payload_j['src'], payload_j['id'])
        return

    def send_client_ack(self, peer, id):
        msg_to_client = json.dumps(
            {'type': 'ack', 'src': self.user.id, 'dst': peer, 'id': id})
        payload_to_server = self.sec.encrypt_with_symmetric(msg_to_client, self.user.sa_data)
        payload_to_server = base64.encodestring(payload_to_server)
        msg_secure_ciphered = json.dumps({'type': 'secure', 'sa-data': 'not used', 'payload': payload_to_server})
        self.send_message(msg_secure_ciphered)
        return

    def process_client_ack(self, ack_json_from_peer):
        id = ack_json_from_peer['id']
        self.user.waiting_acks.remove(id)
        print "Client ACK: " + id
        self.emit(self.append_msg_id, id, True)
        return

    def send_client_comm(self, text):
        if self.peer_connected is None:
            return
        if self.peers[self.peer_connected].connection_state != 200:
            return
        dst_sym_key = self.peers[self.peer_connected].sa_data
        dst_id = self.peer_connected
        ciphered_data_to_client = base64.encodestring(self.sec.encrypt_with_symmetric(text, dst_sym_key))
        id = self.sec.get_nonce()
        msg_to_client = json.dumps({'type': 'client-com', 'src': self.user.id, 'dst': dst_id, 'id': id, 'data': ciphered_data_to_client})
        self.user.waiting_acks.append(id)
        self.emit(self.append_self_msg, text, id)
        payload_to_server = self.sec.encrypt_with_symmetric(msg_to_client, self.user.sa_data)
        payload_to_server = base64.encodestring(payload_to_server)
        msg_secure_ciphered = json.dumps({'type': 'secure', 'sa-data': 'not used', 'payload': payload_to_server})
        self.send_message(msg_secure_ciphered)

    def process_client_connect(self, ccj):
        if self.user.connection_state != 200:
            # i am not connected to the server
            return
        if not all(k in ccj.keys() for k in ("src", "dst", "phase", "id", "ciphers")):
            return
        if ccj['src'] in self.peers.keys():
            if self.peers[ccj['src']].connection_state == 200:
                print "already connected"
                return
        if self.peer_connected == ccj['src']:
            print "already connected"
            return
        if ccj['phase'] == 1:
            if ccj['src'] not in self.peers:
                self.peers[ccj['src']] = User(ccj['data'], uid=ccj['src'])
            elif self.peers[ccj['src']].connection_state != 1:
                del self.peers[ccj['src']]
                self.send_client_disconnect(ccj['src'])
                return
            if ccj['ciphers'][0] in SUPPORTED_CIPHER_SUITES:
                ci = ccj['ciphers'][0]
            elif ccj['ciphers'][1] in SUPPORTED_CIPHER_SUITES:
                ci = ccj['ciphers'][1]
            else:
                del self.peers[ccj['src']]
                self.send_client_disconnect(ccj['src'])
                return
            if self.user.ccauth:
                pubkey_pem = self.sec.rsa_public_key_to_pem(self.user.pub_key)
                data = json.dumps({'cert': self.user.get_certificate(), 'key': pubkey_pem, 'key_sign': self.user.sign(pubkey_pem)})
            else:
                data = self.user.name
            self.send_client_connect(data, ccj, 2, ci)
            self.peers[ccj['src']].connection_state = 2

        elif ccj['phase'] == 2:
            if ccj['src'] not in self.peers:
                self.emit(self.error_signal, "Erro a ligar ao utilizador!")
                self.send_client_disconnect(ccj['src'])
                return
            if self.peers[ccj['src']].connection_state != 2:
                del self.peers[ccj['src']]
                self.emit(self.error_signal, "Erro a ligar ao utilizador!")
                self.send_client_disconnect(ccj['src'])
                return
            if ccj['ciphers'] not in SUPPORTED_CIPHER_SUITES:
                self.error_client_connect_phase2(ccj['src'], ccj, "Unsupported cipher suite")
                return
            data = "ok b0ss"
            try:
                cert_and_key = json.loads(ccj['data'])
            except:
                if self.user.ccauth:
                    pubkey_pem = self.sec.rsa_public_key_to_pem(self.user.pub_key)
                    data = json.dumps({'cert': self.user.get_certificate(), 'key': pubkey_pem,
                                       'key_sign': self.user.sign(pubkey_pem)})
                self.peers[ccj['src']].cipher_suite = ccj['ciphers']
                self.peers[ccj['src']].connection_state = 3
            else:
                if not all(k in cert_and_key.keys() for k in ("cert", "key", "key_sign")):
                    self.error_client_connect_phase2(ccj['src'], ccj, "Erro a ligar ao utilizador! (Missing fields)")
                    return
                if not self.verify_connecting_user(self.peers[ccj['src']], cert_and_key):
                    self.error_client_connect_phase2(ccj['src'], ccj, "Erro a ligar ao utilizador! (Invalid certificate)")
                    return
                self.peers[ccj['src']].ccauth = True
                self.peers[ccj['src']].pub_key = self.sec.rsa_public_pem_to_key(str(cert_and_key['key']))
                if self.user.ccauth:
                    pubkey_pem = self.sec.rsa_public_key_to_pem(self.user.pub_key)
                    data = json.dumps({'cert': self.user.get_certificate(), 'key': pubkey_pem,
                                       'key_sign': self.user.sign(pubkey_pem)})
                self.peers[ccj['src']].cipher_suite = ccj['ciphers']
                self.peers[ccj['src']].connection_state = 3
            self.send_client_connect(data, ccj, 3, ccj['ciphers'])

        elif ccj['phase'] == 3:
            if ccj['src'] not in self.peers:
                self.send_client_disconnect(ccj['src'])
                return
            if self.peers[ccj['src']].connection_state != 2:
                del self.peers[ccj['src']]
                self.send_client_disconnect(ccj['src'])
                return
            if ccj['data'] == "not supported":
                del self.peers[ccj['src']]
                self.send_client_disconnect(ccj['src'])
                return
            if ccj['data'] == "ok b0ss":
                data = self.client_connect_phase3(ccj)
            else:
                try:
                    cert_and_key = json.loads(ccj['data'])
                except:
                    del self.peers[ccj['src']]
                    self.send_client_disconnect(ccj['src'])
                    return
                if not self.verify_connecting_user(self.peers[ccj['src']], cert_and_key):
                    print "ERROR invalid certificate, phase 3"
                    del self.peers[ccj['src']]
                    self.send_client_disconnect(ccj['src'])
                    return
                self.peers[ccj['src']].ccauth = True
                self.peers[ccj['src']].pub_key = self.sec.rsa_public_pem_to_key(str(cert_and_key['key']))
                data = self.client_connect_phase3(ccj)
            msg = {"type": "client-connect", 'id': self.sec.get_nonce(), "src": self.user.id, "dst": ccj['src'],
                   "phase": 4, "ciphers": ccj['ciphers'], "data": data}
            if self.user.ccauth:
                msg['sign'] = self.sec.rsa_sign_with_private_key(msg['id']+msg['dst']+msg['src']+msg['data'], self.user.priv_key)
            msg = json.dumps(msg)
            ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.user.sa_data))
            secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
            self.send_message(json.dumps(secure_msg))
            self.peers[ccj['src']].connection_state = 3

        elif ccj['phase'] == 4:
            if ccj['src'] not in self.peers:
                self.emit(self.error_signal, "Erro a ligar ao utilizador!")
                self.send_client_disconnect(ccj['src'])
                return
            if self.peers[ccj['src']].connection_state != 3:
                self.emit(self.error_signal, "Erro a ligar ao utilizador!")
                self.send_client_disconnect(ccj['src'])
                del self.peers[ccj['src']]
                return
            if ccj['ciphers'] != self.peers[ccj['src']].cipher_suite:
                self.emit(self.error_signal, "Erro a ligar ao utilizador!")
                self.send_client_disconnect(ccj['src'])
                del self.peers[ccj['src']]
                return
            if self.peers[ccj['src']].ccauth:
                if 'sign' not in ccj.keys():
                    self.emit(self.error_signal, "Erro a ligar ao utilizador! (Missing fields)")
                    self.send_client_disconnect(ccj['src'])
                    del self.peers[ccj['src']]
                    return
                if not self.sec.rsa_verify_with_public_key(ccj['sign'], ccj['id']+ccj['dst']+ccj['src']+ccj['data'], self.peers[ccj['src']].pub_key):
                    self.emit(self.error_signal, "Erro a ligar ao utilizador! (Invalid signature)")
                    self.send_client_disconnect(ccj['src'])
                    del self.peers[ccj['src']]
                    return
            if self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                user_pubkey = self.sec.rsa_public_pem_to_key(base64.decodestring(ccj['data']))
                self.peers[ccj['src']].sa_data = self.sec.generate_key_symmetric()
                to_send = self.sec.rsa_encrypt_with_public_key(self.peers[ccj['src']].sa_data, user_pubkey)
                to_send = base64.encodestring(to_send)
                msg = {"type": "client-connect", 'id': self.sec.get_nonce(), "src": self.user.id, "dst": ccj['src'],
                       "phase": 5, "ciphers": ccj['ciphers'], "data": to_send}
                self.peers[ccj['src']].conn_check = self.sec.get_hash(bytes(str(msg['id']) + msg['data']))
            elif self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                priv_key, pub_key = self.sec.ecdh_gen_key_pair()
                peer_key = self.sec.rsa_public_pem_to_key(base64.decodestring(ccj['data']))
                self.peers[ccj['src']].sa_data = self.sec.ecdh_get_shared_secret(priv_key, peer_key)
                del priv_key
                msg = {"type": "client-connect", 'id': self.sec.get_nonce(), "src": self.user.id, "dst": ccj['src'],
                       "phase": 5, "ciphers": ccj['ciphers'],
                       "data": base64.encodestring(self.sec.rsa_public_key_to_pem(pub_key))}
            else:
                return
            if self.user.ccauth:
                msg['sign'] = self.sec.rsa_sign_with_private_key(msg['id'] + msg['dst'] + msg['src'] + msg['data'], self.user.priv_key)
            ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(json.dumps(msg), self.user.sa_data))
            secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
            self.send_message(json.dumps(secure_msg))
            self.peers[ccj['src']].connection_state = 4

        elif ccj['phase'] == 5:
            if ccj['src'] not in self.peers:
                self.send_client_disconnect(ccj['src'])
                return
            if self.peers[ccj['src']].connection_state != 3:
                self.send_client_disconnect(ccj['src'])
                del self.peers[ccj['src']]
                return
            if ccj['ciphers'] != self.peers[ccj['src']].cipher_suite:
                self.send_client_disconnect(ccj['src'])
                del self.peers[ccj['src']]
                return
            if self.peers[ccj['src']].ccauth:
                if 'sign' not in ccj.keys():
                    self.emit(self.error_signal, "Erro a ligar ao utilizador! (Missing fields)")
                    self.send_client_disconnect(ccj['src'])
                    del self.peers[ccj['src']]
                    return
                if not self.sec.rsa_verify_with_public_key(ccj['sign'], ccj['id']+ccj['dst']+ccj['src']+ccj['data'], self.peers[ccj['src']].pub_key):
                    self.emit(self.error_signal, "Erro a ligar ao utilizador! (Invalid signature)")
                    self.send_client_disconnect(ccj['src'])
                    del self.peers[ccj['src']]
                    return
            if self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                self.peers[ccj['src']].sa_data = self.sec.rsa_decrypt_with_private_key(base64.decodestring(ccj['data']), self.peers[ccj['src']].sa_data)
                to_send = self.sec.encrypt_with_symmetric(
                    self.sec.get_hash(bytes(str(ccj['id']) + ccj['data'])), self.peers[ccj['src']].sa_data)
                to_send = base64.encodestring(to_send)
            elif self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                peer_key = self.sec.rsa_public_pem_to_key(base64.decodestring(ccj['data']))
                self.peers[ccj['src']].sa_data = self.sec.ecdh_get_shared_secret(
                    self.peers[ccj['src']].sa_data, peer_key)
                to_send = "ok ecdh done"
            else:
                return
            msg = {"type": "client-connect", 'id': self.sec.get_nonce(), "src": self.user.id,
                   "dst": ccj['src'], "phase": 6, "ciphers": ccj['ciphers'], "data": to_send}
            if self.user.ccauth:
                msg['sign'] = self.sec.rsa_sign_with_private_key(msg['id'] + msg['dst'] + msg['src'] + msg['data'],
                                                                 self.user.priv_key)
            ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(json.dumps(msg), self.user.sa_data))
            secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
            self.send_message(json.dumps(secure_msg))
            self.peers[ccj['src']].connection_state = 200
            self.emit(self.change_list, ccj['src'])
            print "connected to peer \n\n\n\n"

        elif ccj['phase'] == 6:
            if ccj['src'] not in self.peers:
                self.emit(self.error_signal, "Erro a ligar ao utilizador!")
                self.send_client_disconnect(ccj['src'])
                return
            if self.peers[ccj['src']].connection_state != 4:
                self.emit(self.error_signal, "Erro a ligar ao utilizador!")
                self.send_client_disconnect(ccj['src'])
                del self.peers[ccj['src']]
                return
            if ccj['ciphers'] != self.peers[ccj['src']].cipher_suite:
                self.emit(self.error_signal, "Erro a ligar ao utilizador!")
                self.send_client_disconnect(ccj['src'])
                del self.peers[ccj['src']]
                return
            if self.peers[ccj['src']].ccauth:
                if 'sign' not in ccj.keys():
                    self.emit(self.error_signal, "Erro a ligar ao utilizador! (Missing fields)")
                    self.send_client_disconnect(ccj['src'])
                    del self.peers[ccj['src']]
                    return
                if not self.sec.rsa_verify_with_public_key(ccj['sign'], ccj['id']+ccj['dst']+ccj['src']+ccj['data'], self.peers[ccj['src']].pub_key):
                    self.emit(self.error_signal, "Erro a ligar ao utilizador! (Invalid signature)")
                    self.send_client_disconnect(ccj['src'])
                    del self.peers[ccj['src']]
                    return
            if self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
                check = self.sec.decrypt_with_symmetric(base64.decodestring(ccj['data']), self.peers[ccj['src']].sa_data)
                if check != self.peers[ccj['src']].conn_check:
                    self.emit(self.error_signal, "Erro a ligar ao utilizador! (shared secret error)")
                    self.send_client_disconnect(ccj['src'])
                    del self.peers[ccj['src']]
                    return
                del self.peers[ccj['src']].conn_check
            elif self.peers[ccj['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
                if ccj['data'] != "ok ecdh done":
                    self.emit(self.error_signal, "Erro a ligar ao utilizador! (shared secret error)")
                    self.send_client_disconnect(ccj['src'])
                    del self.peers[ccj['src']]
                    return
            self.peers[ccj['src']].connection_state = 200
            print "connected phase 6"
            self.peer_connected = ccj['src']
            self.emit(self.signal, "Connected")

    def client_connect_phase3(self, req):
        self.peers[req['src']].cipher_suite = req['ciphers']
        if self.peers[req['src']].cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
            priv_key, pub_key = self.sec.rsa_gen_key_pair()
            self.peers[req['src']].sa_data = priv_key
            del priv_key
            data = base64.encodestring(self.sec.rsa_public_key_to_pem(pub_key))
            return data
        elif req['ciphers'] == SUPPORTED_CIPHER_SUITES[1]:
            priv_key, pub_key = self.sec.ecdh_gen_key_pair()
            self.peers[req['src']].sa_data = priv_key
            del priv_key
            data = base64.encodestring(self.sec.rsa_public_key_to_pem(pub_key))
            return data
        else:
            return None

    def send_client_connect(self, data, req, phase, ci):
        print type(data)
        msg = json.dumps(
            {"type": "client-connect", 'id': self.sec.get_nonce(), "src": self.user.id, "dst": req['src'],
             "phase": phase, "ciphers": ci, "data": data})
        print msg
        print type(msg)
        ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(str(msg), self.user.sa_data))
        secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
        self.send_message(json.dumps(secure_msg))

    def error_client_connect_phase2(self, sender, req, erro):
        self.emit(self.error_signal, erro)
        del self.peers[sender]
        msg = json.dumps(
            {"type": "client-connect", 'id': self.sec.get_nonce(), "src": self.user.id, "dst": sender,
             "phase": 3, "ciphers": req['ciphers'], "data": "not supported"})
        ciphered_pl = base64.encodestring(self.sec.encrypt_with_symmetric(msg, self.user.sa_data))
        secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
        self.send_message(json.dumps(secure_msg))

    def start_client_connect(self, dst, cipher_suite=1):
        if dst == self.peer_connected:
            return
        if self.peers[dst].connection_state == 200:
            self.peer_connected = dst
            self.emit(self.signal, "Connected")
            for temp in self.peers[dst].buffin.split(TERMINATOR):
                if temp != "\n" and temp != "":
                    self.emit(self.signal, temp)
            self.peers[dst].buffin = ""
            return
        else:
            # if cipher_suite == 1 RSA
            # if cipher_suite == 2 ECDH
            if cipher_suite == 1:
                msg = json.dumps(
                    {"type": "client-connect", 'id': self.sec.get_nonce(), "src": self.user.id, "dst": dst, "phase": 1,
                     "ciphers": SUPPORTED_CIPHER_SUITES, "data": self.user.name})
            else:
                msg = json.dumps(
                    {"type": "client-connect", 'id': self.sec.get_nonce(), "src": self.user.id, "dst": dst, "phase": 1,
                     "ciphers": [SUPPORTED_CIPHER_SUITES[1], SUPPORTED_CIPHER_SUITES[0], SUPPORTED_CIPHER_SUITES[2]],
                     "data": self.user.name})
            ciphered_pl = self.sec.encrypt_with_symmetric(msg, self.user.sa_data)
            ciphered_pl = base64.encodestring(ciphered_pl)
            secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
            self.send_message(json.dumps(secure_msg))
            self.peers[dst].connection_state = 2

    def send_client_disconnect(self, peer):
        if peer in self.peers.keys():
            del self.peers[peer]
        if self.peer_connected == peer:
            self.peer_connected = None
        msg = json.dumps({"type": "client-disconnect", 'id': self.sec.get_nonce(), "src": self.user.id, "dst": peer})
        ciphered_pl = self.sec.encrypt_with_symmetric(msg, self.user.sa_data)
        ciphered_pl = base64.encodestring(ciphered_pl)
        secure_msg = {'type': 'secure', 'sa-data': 'aa', 'payload': ciphered_pl}
        self.send_message(json.dumps(secure_msg))
        self.get_user_lists()

    def process_client_disconnect(self, cdj):
        if not self.user.connection_state == 200:
            return
        if cdj['src'] not in self.peers.keys():
            return
        if self.peers[cdj['src']].connection_state != 200:
            self.emit(self.error_signal, "Erro no peer")
        del self.peers[cdj['src']]
        if self.peer_connected == cdj['src']:
            self.peer_connected = None
        self.get_user_lists()
        return

    def get_user_lists(self):
        get_list = {'type': 'list', 'data': 'passa ai os users sff'}
        get_list = self.sec.encrypt_with_symmetric(json.dumps(get_list), self.user.sa_data)
        get_list = base64.encodestring(get_list)
        msg = {'type': 'secure', 'sa-data': 'aa', 'payload': get_list}
        self.send_message(json.dumps(msg))

    def process_list(self, data):
        if 'data' not in data.keys():
            return
        for u in data['data']:
            if u['id'] not in self.peers.keys():
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
            {"type": "connect", "phase": int(phase), "name": name, "id": id, "ciphers": ciphers, "data": data, "nonce": self.sec.get_nonce()})

    def verify_connecting_user(self, user, json):
        print "VERIFY CONNECTING USER"
        u_name = user.name
        cert = str(json['cert'])
        j_pub_key = str(json['key'])
        c_pub_key = self.sec.get_pubkey_from_cert(cert)
        print "GOT THE CERT'S PUBKEY"
        c_name = self.sec.get_name_from_cert(cert)
        signature = str(json['key_sign'])
        print "GOT THE CERT'S NAME"
        # verificar nome
        c_name = unicode(c_name, 'utf-8')
        if not u_name == c_name:
            print "DIFF: NAME"
            return False
        # verificar validade do cert
        if not self.sec.verify_certificate(cert):
            print "INVALID CERT"
            return False
        # verificar que assinatura é valida para json['key']
        if not self.sec.rsa_verify_with_public_key(signature, j_pub_key, c_pub_key, pad=PADDING_PKCS1, hash_alg=SHA1):
            print "INVALID SIGNATURE"
            return False
        return True

class ConnectionManagerError(Exception):
    pass
