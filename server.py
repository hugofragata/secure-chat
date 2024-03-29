
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4
from socket import *
from select import *
import json
import sys
import time
import logging
from cryptography.fernet import InvalidToken
from server_crypt_utils import *

# Server address
HOST = "192.168.0.104"   # All available interfaces
PORT = 8081  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2

SUPPORTED_CIPHER_SUITES = ["RSA_WITH_AES_128_CBC_SHA256", "ECDHE_WITH_AES_128_CBC_SHA256", "NONE"]


class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None
        self.num_msg = 0
        self.sa_data = None
        self.level = 0
        self.state = STATE_NONE
        self.name = "Unknown"
        self.cipher_suite = None
        self.pub_key = None
        self.cc = False

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (self.id, str(self.addr), self.name, self.level, self.state)

    def asDict(self):
        return {'name': self.name, 'id': self.id, 'level': self.level}

    def setState(self, state):
        if state not in [STATE_CONNECTED, STATE_NONE, STATE_DISCONNECTED]:
            return

        self.state = state

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            logging.error("Client (%s) buffer exceeds MAX BUFSIZE. %d > %d", 
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        #print reqs
        self.bufin = reqs[-1]
        return reqs[:-1]

    def send(self, obj):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(obj) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)", self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        logging.info("Client.close(%s)", self)
        try:
            # Shutdown will fail on a closed socket...
            self.socket.shutdown(SHUT_RDWR)
            self.socket.close()
        except:
            logging.exception("Client.close(%s)", self)

        logging.info("Client Closed")

    def permission_to_write(self, other):
        '''
        Permissions in Bell Lapadula. Clients with Portuguese CC are higher in the hierarchy.
        This function says if the SELF client can WRITE to the OTHER client
        if SELF is higher than OTHER then refuse write
        :param other: Other Client instance
        :return: Boolean
        '''
        if self.cc and not other.cc:
            return False
        return True

    def permission_to_read(self, other):
        '''
        Permissions in Bell Lapadula. Clients with Portuguese CC are higher in the hierarchy.
        This function says if the SELF client can WRITE to the OTHER client
        if SELF is lower than OTHER then refuse write
        :param other: Other Client instance
        :return: Boolean
        '''
        if not self.cc and other.cc:
            return False
        return True


class ChatError(Exception):
    """This exception should signal a protocol error in a client request.
    It is not a server error!
    It just means the server must report it to the sender.
    It should be dealt with inside handleRequest.
    (It should allow leaner error handling code.)
    """
    pass


def ERROR(msg):
    """Raise a Chat protocol error."""
    raise ChatError(msg)


class Server:
    def __init__(self, host, port):
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        logging.info("Secure IM server listening on %s", self.ss.getsockname())
        # clients to manage (indexed by socket and by name):
        self.clients = {}       # clients (key is socket)
        self.id2client = {}   # clients (key is id)

    def stop(self):
        """ Stops the server closing all sockets
        """
        logging.info("Stopping Server")
        try:
            self.ss.shutdown(SHUT_RDWR)
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.clients:
            try:
                self.clients[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.clients.clear()
        self.id2client.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.clients:
            logging.error("Client NOT Added: %s already exists", self.clients[csock])
            return

        client = Client(csock, addr)
        self.clients[client.socket] = client
        logging.info("Client added: %s", client)

    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            logging.error("Client NOT deleted: %s not found", self.clients[csock])
            return

        client = self.clients[csock]
        assert client.socket == csock, "client.socket (%s) should match key (%s)" % (client.socket, csock)
        del self.id2client[client.id]
        del self.clients[client.socket]
        client.close()
        logging.info("Client deleted: %s", client)
        self.broadcast_new_list(None)

    def accept(self):
        """Accept a new connection.
        """
        try:
            csock, addr = self.ss.accept()
            self.addClient(csock, addr)
        except:
            logging.exception("Could not accept client")

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.clients[s]
        data = None
        try:
            data = s.recv(BUFSIZE)
            logging.info("Received data from %s. Message:\n%r", client, data)
        except:
            logging.exception("flushin: recv(%s)", client)
            logging.error("Received invalid data from %s. Closing", client)
            self.delClient(s)
        else:
            if len(data) > 0:
                reqs = client.parseReqs(data)
                for req in reqs:
                    self.handleRequest(s, req)
            else:
                self.delClient(s)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s not in self.clients:
            # this could happen before, because a flushin might have deleted the client
            logging.error("BUG: Flushing out socket that is not on client list! Socket=%s", str(s))
            return

        client = self.clients[s]
        try:
            sent = client.socket.send(client.bufout[:BUFSIZE])
            logging.info("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent])
            client.bufout = client.bufout[sent:]  # leave remaining to be sent later
        except:
            logging.exception("flushout: send(%s)", client)
            # logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open client connection)
            rlist = [self.ss] + self.clients.keys()
            # sockets to select for writing: (those that have something in bufout)
            wlist = [ sock for sock in self.clients if len(self.clients[sock].bufout)>0 ]
            logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            (rl, wl, xl) = select(rlist, wlist, rlist)
            logging.debug("select: %s %s %s", rl, wl, xl)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.clients:
                    self.flushin(s)
                else:
                    logging.error("Incoming, but %s not in clients anymore", s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.clients:
                    self.flushout(s)
                else:
                    logging.error("Outgoing, but %s not in clients anymore", s)

            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.delClient(s)

    def handleRequest(self, s, request):
        """Handle a request from a client socket.
        """
        client = self.clients[s]
        try:
            logging.info("HANDLING message from %s: %r", client, repr(request))

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
            client.send({'type': 'ack'})

            if req['type'] == 'connect':
                self.processConnect(client, req, request)
            elif req['type'] == 'secure':
                self.processSecure(client, req)
            elif req['type'] == 'disconnect':
                self.delClient(client.socket)
        except Exception, e:
            logging.exception("Could not handle request")

    def clientList(self):
        """
        Return the client list
        """
        cl = []
        for k in self.clients:
            cl.append(self.clients[k].asDict())
        return cl

    def processConnect(self, sender, request, inText):
        """
        Process a connect message from a client
        :param sender: The sender of the request
        :type sender: Client
        """
        if sender.state == STATE_CONNECTED:
            logging.warning("Client is already connected: %s" % sender)
            return

        if not all (k in request.keys() for k in ("name", "ciphers", "phase", "id")):
            logging.warning("Connect message with missing fields")
            return

        if sender.level == 0 and request['phase'] == 1:
            print "LEVEL 0 \n\n"
            if request['ciphers'][0] in SUPPORTED_CIPHER_SUITES:
                sender.cipher_suite = request['ciphers'][0]
            else:
                sender.cipher_suite = request['ciphers'][1]
            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'id': get_nonce(), 'ciphers': sender.cipher_suite,
                   'data': base64.encodestring(get_certificate()), 'sign': sign_data(inText)}
            sender.send(msg)
            self.id2client[request['id']] = sender
            sender.id = request['id']
            sender.name = request['name']
            sender.level = 1
            return
        elif sender.level == 1 and request['phase'] == 3:
            print "LEVEL 1 \n\n"
            if "data" not in request.keys():
                logging.warning("Missing fields")
                self.delClient(sender.socket)
                return
            if request['data'] == 'ok b0ss':
                self.connect_phase3(sender, request)
            elif request['data'] == 'not supported':
                logging.warning("Connect message with missing fields")
                self.delClient(sender.socket)
                return
            else:
                try:
                    cert_and_key = json.loads(request['data'])
                except:
                    logging.warning("Connect message with unknown fields")
                    self.delClient(sender.socket)
                    return
                if 'cert' not in cert_and_key.keys() or 'key' not in cert_and_key.keys() or 'key_sign' not in cert_and_key.keys():
                    logging.warning("Connect message with missing fields")
                    self.delClient(sender.socket)
                    return
                # verify certificate
                if not verify_certificate(cert_and_key['cert']):
                    logging.warning("Invalid certificate for user")
                    self.delClient(sender.socket)
                    return
                user_cc_pubkey = get_pubkey_from_cert(cert_and_key['cert'])
                if sender.name != unicode(get_info_from_cert(cert_and_key['cert'], label="CN"), "utf-8") or sender.id != unicode(get_info_from_cert(cert_and_key['cert'], label="serialNumber"), "utf-8"):
                    logging.warning("User trying to login with a different name or id: " + sender.name)
                    self.delClient(sender.socket)
                    return

                sender.cc = True
                if not rsa_verify_with_public_key(cert_and_key['key_sign'], cert_and_key['key'], user_cc_pubkey,
                                                  pad=PADDING_PKCS1, hash_alg=SHA1):
                    logging.warning("Invalid signature in user")
                    self.delClient(sender.socket)
                    return
                sender.pub_key = rsa_public_pem_to_key(str(cert_and_key['key']))
                self.connect_phase3(sender, request)

        elif sender.level == 2 and request['phase'] == 5:
            print "LEVEL 2 \n\n"
            if 'data' not in request.keys():
                logging.warning("Missing fields")
                self.delClient(sender.socket)
                return
            if sender.cc:
                if 'sign' not in request.keys():
                    logging.warning("Missing fields")
                    self.delClient(sender.socket)
                    return
                if not rsa_verify_with_public_key(request['sign'], request['id'] + request['ciphers'] + request['data'],
                                                  sender.pub_key):
                    logging.warning("INVALID SIGNATURE")
                    self.delClient(sender.socket)
                    return
            self.connect_phase5(sender, request)

    def processList(self, sender):
        """
        Process a list message from a client
        """
        if sender.state != STATE_CONNECTED:
            logging.warning("LIST from disconnected client: %s" % sender)
            return
        if sender.level != 200:
            return

        filtered_client_list = []
        for client in self.clients:
            if sender.permission_to_read(self.clients[client]):
                filtered_client_list.append(self.clients[client].asDict())

        data = json.dumps({'type': 'list', 'data': filtered_client_list})
        self.send_secure(data, sender)

    def broadcast_new_list(self, init):
        for client in self.clients:
            if self.clients[client] != init:
                self.processList(self.clients[client])

    def processSecure(self, sender, request):
        """
        Process a secure message from a client
        """
        if sender.state != STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        # This is a secure message.
        sender.num_msg += 1
        payload = base64.decodestring(request['payload'])
        try:
            plainText_payload = decrypt_with_symmetric(bytes(payload), sender.sa_data)
        except InvalidToken:
            logging.warning("Invalid key or integrity check fail from client %s" % sender)
            return
        payload_json = json.loads(plainText_payload)

        if not 'type' in payload_json.keys():
            logging.warning("Secure message without inner frame type")
            return
        if payload_json['type'] == 'list':
            self.processList(sender)
            return
        if not all(k in payload_json.keys() for k in ("src", "dst")):
            return

        if not payload_json['dst'] in self.id2client.keys():
            logging.warning("Message to unknown client: %s" % payload_json['dst'])
            return

        dst = self.id2client[payload_json['dst']]
        if not sender.permission_to_write(dst) or not dst.permission_to_read(sender):
            logging.warning(str(payload_json['src']) + " no permission to dst:" + str(payload_json['dst']))
            return
        self.send_secure(plainText_payload, dst)

    def connect_phase3(self, sender, request):
        if sender.cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
            priv_key, pub_key = rsa_gen_key_pair()
        elif sender.cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
            priv_key, pub_key = ecdh_gen_key_pair()
        else:
            logging.warning("ERRO")
            self.delClient(sender.socket)
            return
        sender.sa_data = priv_key
        msg = {'type': 'connect', 'phase': request['phase'] + 1, 'id': get_nonce(),
               'ciphers': sender.cipher_suite, 'data': pub_key}
        msg['sign'] = sign_data(msg['id'] + msg['ciphers'] + msg['data'])
        sender.send(msg)
        sender.level = 2
        return

    def connect_phase5(self, sender, request):
        if sender.cipher_suite == SUPPORTED_CIPHER_SUITES[0]:
            sender.sa_data = rsa_decrypt_with_private_key(request['data'], sender.sa_data)
            to_send = encrypt_with_symmetric(get_hash(bytes(str(request['id']) + request['data'])), sender.sa_data)
            to_send = base64.encodestring(to_send)
        elif sender.cipher_suite == SUPPORTED_CIPHER_SUITES[1]:
            peer_key = rsa_public_pem_to_key(str(request['data']))
            sender.sa_data = ecdh_get_shared_secret(sender.sa_data, peer_key)
            to_send = "ok ecdh done"
        else:
            logging.warning("ERRO")
            self.delClient(sender.socket)
            return
        msg = {'type': 'connect', 'phase': request['phase'] + 1, 'id': get_nonce(),
               'ciphers': sender.cipher_suite, 'data': to_send}
        msg['sign'] = sign_data(msg['id'] + msg['ciphers'] + msg['data'])
        sender.send(msg)
        sender.level = 200
        sender.setState(STATE_CONNECTED)
        self.broadcast_new_list(sender)
        logging.info("Client %s Connected" % sender.id)

    def send_secure(self, msg, client):
        '''
        Used to make secure type messages
        :param msg: msg to encrypt
         :type msg: string
        :param client: message destination
        :type client: Client
        :return:  base64 encoded payload ready to send
        '''
        c_payload = base64.encodestring(encrypt_with_symmetric(msg, client.sa_data))
        dst_message = {'type': 'secure', 'sa-data': 'not used', 'payload': c_payload}
        client.send(dst_message)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    serv = None
    while True:
        try:
            logging.info("Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT)
            serv.loop()
        except KeyboardInterrupt:
            serv.stop()
            try:
                logging.info("Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                logging.info("CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server ERROR")
            if serv is not (None):
                serv.stop()
            time.sleep(10)
