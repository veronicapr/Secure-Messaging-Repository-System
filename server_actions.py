from utils_security import *
from server_registry import *



class ServerActions:
    """Server Actions - Contain the list of processes made by the server upon receiving a new client task."""

    def __init__(self):
        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus
        }
        self.registry = ServerRegistry()
        self.debug = False
        (public_key, private_key) = rsa.newkeys(512)
        self.public_key = public_key
        self.private_key = private_key

    def handleRequest(self, s, received_request, client):
        """Handle a request from a client socket."""
        print("===== Handle Request =====")
        log(logging.INFO, "HANDLING message from %s" % client)
        # client is out
        if received_request == '':
            log(logging.INFO, "Client is out" % client)
            return
        # decipher message from client if session key already created
        try:
            if client.connection_aes is None:
                request = json.loads(received_request)
            else:
                request = json.loads(client.connection_aes.decrypt(received_request))
        except Exception as exception:
            log(logging.ERROR, "Could not handle request - Decipher: " + str(exception))
            client.sendResult({"error": "unknown request"})
            return
        # show clear request
        log(logging.INFO, "Request: " + str(request))
        # message format is not a dict
        if not isinstance(request, dict):
            log(logging.ERROR, "Invalid message format from client")
            client.sendResult({"error": "unknown request"})
            return
        # if message has no type field
        if not {'type'}.issubset(request.keys()):
            log(logging.ERROR, "Message has no TYPE field")
            client.sendResult({"error": "unknown request"})
            return
        # if known type
        if request['type'] not in self.messageTypes:
            log(logging.ERROR,
                "Invalid message type: %s Should be one of: %s" % (str(request['type']), str(self.messageTypes.keys())))
            client.sendResult({"error": "unknown request"})
            return
        # verify integrity
        if request['type'] in {'all', 'new', 'send', 'recv', 'receipt', 'status'}:
            # Message Counter
            if not {'counter'}.issubset(request.keys()):
                log(logging.ERROR, "Message has no COUNTER field")
                client.sendResult({"error": "unknown request"})
                return
            else:
                if int(request['counter']) == client.msg_counter:
                    client.msg_counter += 1
                else:
                    log(logging.ERROR, "Messages might be corrupted")
                    client.sendResult({"error": "could not handle request"})
                    return
            if not {'signature'}.issubset(request.keys()):
                log(logging.ERROR, "Message has no signature field")
                client.sendResult({"error": "unknown request"})
                return
            # get signature
            signature = request['signature']
            del request['signature']
            if 'uid' in request.keys():
                user_id = self.registry.getUuidFromUid(int(request['uid']))
            elif 'src' in request.keys():
                user_id = request['src']
            else:
                user_id = request['uuid']
            pub_key = self.registry.getUserPubKey(user_id)
            public_key = rsa.PublicKey.load_pkcs1(keyfile=pub_key, format='PEM')
            sign = base64.b64decode(signature)
            str_request = json.dumps(request, sort_keys=True)
            try:
                rsa.verify(message=str_request, signature=sign, pub_key=public_key)
            except rsa.VerificationError, rsa.DecryptionError:
                log(logging.ERROR, "Message was modified midway")
                client.sendResult({"error": "could not handle request"})
                return
        tipo = request['type']
        # process request
        if self.debug:
            response = self.messageTypes[tipo](request, client)
        else:
            try:
                response = self.messageTypes[tipo](request, client)
            except Exception as exception:
                    log(logging.ERROR, "Could not handle request: " + str(exception))
                    client.sendResult({"error": "could not handle request"})
                    return
        # skip None
        if response is None:
            return
        # don't sign
        if 'type' in response.keys():
            shared_secret = response['shared_secret']
            del response['shared_secret']
            client.sendResult(response)
            client.connection_aes = AESCipher(shared_secret)
            return
        if (tipo in {'list', 'create'}) and ('error' not in response.keys()):
            client.sendResult(response)
            return
        if tipo in {'all', 'new', 'send', 'recv', 'receipt', 'status'}:
            response['counter'] = client.msg_counter
            client.msg_counter += 1
        # case its an error message
        if 'error' in response.keys():
            client.sendResult(response)
            return
        # sign response
        test = json.dumps(response, sort_keys=True)
        sign = rsa.sign(message=test, priv_key=self.private_key, hash='SHA-256')
        # add signature
        response['signature'] = base64.b64encode(sign)
        # send
        client.sendResult(response)

    def processCreate(self, data, client):
        """Create request handler"""
        print("===== Create/Retrieve User Request =====")
        # verify send message fields
        if not {'uuid', 'data'}.issubset(data.keys()):
            log(logging.ERROR, "Badly formatted \"create\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        # generate symmetric key
        if not {'cyphers'}.issubset(data['data'].keys()):
            log(logging.ERROR, "Badly formatted \"create\"data\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        # exchange
        if data['data']['cyphers'] == 'exchange':
            # get client DH info
            g = int(data['data']['g'])
            a = long(data['data']['a'])
            # gen b and pair result
            b = DiffieHellman(g)
            shared_secret = b.genKey(a)
            # exchange missing value
            log(logging.INFO, "Exchanging key pair")
            return {
                'result': {'b': str(b.publicKey)},
                'type': 'create',
                'shared_secret': str(shared_secret)
            }
        # info retrieval
        elif data['data']['cyphers'] == 'DH':
            # deletes data cyphers from user description
            del data['data']['cyphers']
            # try to verify
            if not self.registry.card_utils.verify_signature(certificate_pem=data['data']['certificate'],
                                                    signature=data['data']['signature'],
                                                    text=data['data']['personal_public_key'].encode('ascii')):
                return {"error": "user verification"}
            del data['data']['signature']
            # uuid already exist
            if self.registry.userExists(data['uuid']):
                log(logging.INFO, "User %s already exists, retrieving" % (data['uuid']))
                me = self.registry.getVerifiedUser(data['uuid'], data)
                if not me:
                    return {"error": "user retrieval"}
                else:
                    return {"result": {'id': me.id, 'server_public_key_pem': self.public_key.save_pkcs1(format='PEM')}}
            # uuid doesn't exist
            else:
                log(logging.INFO, "User %s doesn't exist, creating" % (data['uuid']))
                me = self.registry.addUser(data, data['uuid'])
                if not me:
                    return {"error": "user creation"}
                else:
                    return {"result": {'id': me.id}, 'server_public_key_pem': self.public_key.save_pkcs1(format='PEM')}
        else:
            log(logging.ERROR, "Invalid cipher parameters")
            return {"error": "wrong message format"}

    def processList(self, data, client):
        """User list request handler"""
        print("===== List Users Request =====")
        # check for id in data, if there is none uses default None [all users]
        if 'user_uuid' in data.keys():
            user_uuid = str(data['user_uuid'])
        else:
            user_uuid = None
        # retrieve user list
        return {"result": {'user_list': self.registry.listUsers(user_uuid)}}

    def processNew(self, data, client):
        """New messages request handle"""
        print("===== New Message Request =====")
        # verify send message fields
        if not {'uid'}.issubset(data.keys()):
            log(logging.ERROR, "Badly formatted \"new\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        try:
            # check if id is the correct number
            uid = int(data['uid'])
        except ValueError:
            log(logging.ERROR, "No valid \"uid\" field in \"new\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        # send both received and sent messages list
        return {"result": self.registry.userNewMessages(uid)}

    def processAll(self, data, client):
        """All messages request handle"""
        print("===== All Messages Request =====")
        # verify send message fields
        if not {'uid'}.issubset(data.keys()):
            log(logging.ERROR, "Badly formatted \"all\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        try:
            # check if id is the correct number
            uid = int(data['uid'])
        except ValueError:
            log(logging.ERROR, "No valid \"id\" field in \"all\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        # send both received and sent messages list
        return {'result': {'received': self.registry.userAllMessages(uid), 'sent': self.registry.userSentMessages(uid)}}

    def processSend(self, data, client):
        """Send message request handler"""
        print("===== Send Message Request =====")
        # verify send message fields
        if not {'src', 'dst', 'msg', 'copy'}.issubset(data.keys()):
            log(logging.ERROR, "Badly formatted \"send\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        if not {'message', 'signature', 'certificate_dst'}.issubset(data['msg'].keys()):
            log(logging.ERROR, "Badly formatted \"send\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        if not self.registry.userExists(str(data['src'])):
            log(logging.ERROR, "Unknown source id for \"send\" message: " + json.dumps(data))
            return {"error": "wrong parameters"}
        if not self.registry.userExists(str(data['dst'])):
            log(logging.ERROR, "Unknown destination id for \"send\" message: " + json.dumps(data))
            return {"error": "wrong parameters"}
        # send message to respective target boxes
        return {"result": self.registry.sendMessage(data['src'], data['dst'], data['msg'], data['copy'])}

    def processRecv(self, data, client):
        """Receive message request handle"""
        print("===== Receive Message Request =====")
        # verify receive message fields
        if not {'uid', 'msg'}.issubset(data.keys()):
            log(logging.ERROR, "Badly formatted \"recv\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        # retrieve uuid from data
        user_uuid = self.registry.getUuidFromUid(int(data['uid']))
        # additional pre-checks
        if not self.registry.userExists(user_uuid):
            log(logging.ERROR, "Unknown source uid for \"recv\" message: " + json.dumps(data))
            return {"error": "wrong parameters"}
        if not self.registry.messageExists(user_uuid, str(data['msg'])):
            log(logging.ERROR, "Unknown source msg for \"recv\" message: " + json.dumps(data))
            return {"error": "wrong parameters"}
        # Read message
        return {"result": self.registry.recvMessage(int(data['uid']), str(data['msg']))}

    def processReceipt(self, data, client):
        """Receipt message request handler"""
        print("===== Receipt Message Request =====")
        # verify receive message fields
        if not {'uid', 'msg', 'receipt'}.issubset(data.keys()):
            log(logging.ERROR, "Badly formatted \"receipt\" message: " + json.dumps(data))
            return None
        # verify if message is already read
        if self.registry.messageWasRead(int(data['uid']), str(data['msg'])):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            return None
        # stores receipt
        self.registry.storeReceipt(int(data['uid']), data['msg'], data['receipt'])
        return None

    def processStatus(self, data, client):
        """Status request handler"""
        print("===== Status Request =====")
        # verify receive message fields
        if not {'uid', 'msg'}.issubset(data.keys()):
            log(logging.ERROR, "Badly formatted \"receipt\" message: " + json.dumps(data))
            return {"error": "wrong message format"}
        # verify if a copy of the message exists
        if not self.registry.copyExists(int(data['uid']), str(data['msg'])):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            return {"error", "wrong parameters"}
        # get message status
        return {"result": self.registry.getReceipts(int(data['uid']), str(data["msg"]))}
