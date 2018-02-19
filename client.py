import json
import uuid
import socket
import sys
import getpass
import datetime
import rsa
import time

from utils_citizen_card import *
from utils_security import *
from collections import OrderedDict


class Client:
    """Client used in the connections between the client and the server"""
    def __init__(self, buffer_size, terminator, debug=False):
        # server info
        self.buffer_size = buffer_size
        self.terminator = terminator
        # folders and files
        self.folder_clients = "info_clients"
        self.filename_public = "public"
        self.filename_private = "private"
        self.filename_hash = "hash"
        self.filename_cert = "certificate"
        # others
        self.debug = debug
        self.card_utils = CitizenCardUtils()
        self.client_info = {}
        self.server_public_key_pem = None
        self.server_public_key = None
        self.message_counter = 0

    def client_menu(self):
        """Creates client menu and asks for him to choose an option"""
        # create menu
        menu = {'1': "See new messages.",
                '2': "See all messages.",
                '3': "List all users.",
                '4': "Send message.",
                '5': "Status.",
                '6': "Exit."}
        # menu cycle
        while True:
            # print menu
            options = menu.keys()
            options.sort()
            print ""
            for entry in options:
                print entry, menu[entry]
            # option selection
            selection = raw_input("Please Select: ")
            print ""
            # process option
            if selection == '1':
                # ===== ===== New Messages ===== ===== #
                self.perform_new()
            elif selection == '2':
                # ===== ===== All Messages ===== ===== #
                self.perform_all()
            elif selection == '3':
                # ===== ===== User List ===== ===== #
                self.perform_list()
            elif selection == '4':
                # ===== ===== Send Message ===== ===== #
                self.perform_send()
            elif selection == '5':
                # ===== ===== Message Status ===== ===== #
                self.perform_status()
            elif selection == '6':
                break
            else:
                print "Unknown Option Selected!"

    def create_retrieve_client(self):
        """Tries to retrieve client info according to given username, creates new one otherwise"""
        # ask for user information
        username = raw_input("Username: ")
        user_password = getpass.getpass("Password: ")
        # convert username to uuid and digest password
        user_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, username)
        user_uuid = str(user_uuid)

        # ===== ===== Pre verifications ===== ===== #
        # check for clients keys folder, create one if none exists
        try:
            if not os.path.exists(self.folder_clients):
                os.mkdir(self.folder_clients)
        except Exception as exception:
            if self.debug:
                print exception
            sys.exit("Cannot create directory " + self.folder_clients)
        # creates folder for user if there isn't one
        try:
            if not os.path.exists(os.path.join(self.folder_clients, user_uuid)):
                os.mkdir(os.path.join(self.folder_clients, user_uuid))
        except Exception as exception:
            if self.debug:
                print exception
            sys.exit("Cannot create directory " + user_uuid)

        # ===== ===== Password verification ===== ===== #
        # pre verifications
        length_username = (4 if len(username) == 0 else len(username))
        length_password = (4 if len(user_password) == 0 else len(user_password))
        # calculate salt
        salt = length_username * len(user_uuid) * length_password
        # digest
        password_digest = hashlib.sha256(user_password + str(salt) + username).digest()
        # pre verifications
        exists_hash = os.path.exists(os.path.join(self.folder_clients, user_uuid, self.filename_hash))
        # compare if hash file exists
        if exists_hash:
            with open(os.path.join(self.folder_clients, user_uuid, self.filename_hash), 'r') as f:
                if not f.read() == password_digest:
                    if self.debug:
                        print "Password different"
                        return
                    return {}
        # creates a password if there isn't one
        else:
            # save password digest
            with open(os.path.join(self.folder_clients, user_uuid, self.filename_hash), 'w') as f:
                f.write(password_digest)
        # ===== ===== RSA Check / Generate ===== ===== #
        # pre verifications
        exists_public = os.path.exists(os.path.join(self.folder_clients, user_uuid, self.filename_public))
        exists_private = os.path.exists(os.path.join(self.folder_clients, user_uuid, self.filename_private))
        # create aes
        private_aes = AESCipher(user_password + str(salt) + username)
        # test RSA if they exist
        if exists_public and exists_private:
            try:
                with open(os.path.join(self.folder_clients, user_uuid, self.filename_public), 'r') as f:
                    pem_key = f.read()
                    public_key = rsa.PublicKey.load_pkcs1(keyfile=pem_key, format="PEM")
                with open(os.path.join(self.folder_clients, user_uuid, self.filename_private), 'r') as f:
                    file_contents = f.read()
                    pem_key = private_aes.decrypt(file_contents)
                    private_key = rsa.PrivateKey.load_pkcs1(keyfile=pem_key, format="PEM")
            except Exception as exception:
                if self.debug:
                    print exception
                sys.exit("Can't read keys, please delete them for re-generation")
        # creates new keys if none are found
        else:
            # create keys
            (public_key, private_key) = rsa.newkeys(512)
            # save keys
            with open(os.path.join(self.folder_clients, user_uuid, self.filename_private), 'w') as f:
                private_key_pem = private_key.save_pkcs1(format='PEM')
                encrypted_private_key_pem = private_aes.encrypt(private_key_pem)
                f.write(encrypted_private_key_pem)
            with open(os.path.join(self.folder_clients, user_uuid, self.filename_public), 'w') as f:
                public_key_pem = public_key.save_pkcs1(format='PEM')
                f.write(public_key_pem)

        # ===== ===== Finish creation ===== ===== #
        # returns dict with user base infos
        return {
            'aes_connection': None,
            'aes_private_key': private_aes,
            'uid': 0,
            'user_uuid': user_uuid,
            'private_key': private_key,
            'public_key': public_key
        }

    def send_and_receive(self, message):
        """Send request message to server and receive result form it"""
        # add signature of entire message
        if message['type'] not in {'create', 'list'}:
            # add message counter to the message
            message['counter'] = self.message_counter
            self.message_counter += 1
            # convert
            test = json.dumps(message, sort_keys=True)
            # signature
            signature = rsa.sign(message=test, priv_key=self.client_info['private_key'], hash='SHA-256')
            base64_signature = base64.b64encode(signature)
            message['signature'] = base64_signature
        # send to server
        request_str = json.dumps(message) + self.terminator
        # cypher with aes
        if self.client_info['aes_connection'] is None:
            sock.send(request_str)
        else:
            sock.send(self.client_info['aes_connection'].encrypt(request_str))
        # move on if message is an receipt
        if message['type'] == 'receipt':
            return None

        while True:
            # receive data from server
            accept_raw_data = sock.recv(self.buffer_size)
            accept_data_str = accept_raw_data.split(self.terminator)[0]
            # load dictionary
            if self.client_info['aes_connection'] is None:
                accept_data_json = json.loads(accept_data_str)
            else:
                accept_data_json = json.loads(self.client_info['aes_connection'].decrypt(accept_data_str))
            # read only responses
            if message['type'] in {'list', 'create'}:
                break
            # counter in response
            if 'counter' in accept_data_json.keys():
                counter = accept_data_json['counter']
                if counter == self.message_counter:
                    self.message_counter += 1
                    break
        # if error in message
        if 'error' in accept_data_json.keys():
            if self.debug:
                print accept_data_json['error']
            return None
        # read only responses
        if message['type'] in {'list', 'create'}:
            return accept_data_json['result']
        # check server message integrity by checking signature
        base64_signature = accept_data_json['signature']
        del accept_data_json['signature']
        # get ordered text and signature
        test = json.dumps(accept_data_json, sort_keys=True)
        signature = base64.b64decode(base64_signature)
        # try to verify the message, any raised error will result in a discard of the response
        try:
            rsa.verify(message=test, signature=signature, pub_key=self.server_public_key)
        except rsa.VerificationError, rsa.DecryptionError:
            return None
        # accept response
        return accept_data_json['result']

    def request_create(self, data):
        """Sends request for user creation and returns the id form the server"""
        # message to send
        create_msg = {'type': 'create', 'uuid': str(self.client_info['user_uuid']), 'data': data}
        # send request
        return self.send_and_receive(message=create_msg)

    def perform_create(self):
        """Creates connection with the server and returns the symmetric key associated with the connection"""
        # ===== ===== Create message and Diffie Hellman Keys exchange ===== ===== #
        # gen client values
        g = 7
        a = DiffieHellman(g)
        # data to be sent
        data = {'cyphers': 'exchange', 'g': g, 'a': a.publicKey}
        # receive result
        result = self.request_create(data=data)
        if result is None:
            print "Error in server request process"
            return
        # determine key
        client_key = a.genKey(long(result['b']))
        # create AES cipher
        self.client_info['aes_connection'] = AESCipher(str(client_key))

        # ===== ===== Build client info ===== ===== #
        # get all the citizen card certificates
        certificates = self.card_utils.get_citizen_certificates()
        # create type and client info
        data = {'cyphers': 'DH', 'personal_public_key': self.client_info['public_key'].save_pkcs1(format='PEM')}
        # get subject info from certificate
        for certificate in certificates:
            if certificate['TYPE'] in {'CITIZEN AUTHENTICATION CERTIFICATE'}:
                data['certificate'] = certificate['CERTIFICATE_PEM']
        # signature of the public key
        data['signature'] = self.card_utils.sign(
            text=self.client_info['public_key'].save_pkcs1(format='PEM'), key_type='AUTHENTICATION')
        # send information to server
        result = self.request_create(data=data)
        if result is None:
            print "Error in server request process"
            return
        # retrieve uid
        print(str(result))
        self.client_info['uid'] = int(result['id'])
        self.server_public_key_pem = result['server_public_key_pem']
        self.server_public_key = rsa.PublicKey.load_pkcs1(keyfile=self.server_public_key_pem, format='PEM')

    def request_list(self):
        """Sends request for user list"""
        # message to send
        list_msg = {'type': 'list'}
        # send request
        return self.send_and_receive(message=list_msg)

    def perform_list(self):
        """Sends request for user list"""
        # request for user list
        result = self.request_list()
        if result is None:
            print "Error in server request process"
            return
        user_list = result['user_list']
        if not user_list:
            # no users
            print "There are no users."
        else:
            # display users
            print "Users connected to the Message Box:"
            for user in user_list:
                subject_info = self.card_utils.get_certificate_subject_info(user['certificate'])
                if user['user_uuid'] == self.client_info['user_uuid']:
                    print "\t" + subject_info['cc_number'][2:] + " - " + subject_info['complete_name'] + " -> Me"
                else:
                    print "\t" + subject_info['cc_number'][2:] + " - " + subject_info['complete_name']

    def request_send(self, source_uuid, destination_uuid, message, copy):
        """Sends request for message send"""
        # message to send
        send_msg = {'type': 'send', 'src': source_uuid, 'dst': destination_uuid, 'msg': message, 'copy': copy}
        # send request
        return self.send_and_receive(message=send_msg)

    def perform_send(self):
        """Sends message to selected user"""
        # request for user list
        result = self.request_list()
        if result is None:
            print "Error in server request process"
            return
        # get list
        user_list = result['user_list']
        # no users
        if not user_list:
            print "There are no users."
            return
        # display users
        print "Please choose an user to communicate with:"
        user_cnt = 1
        for user in user_list:
            subject_info = self.card_utils.get_certificate_subject_info(user['certificate'])
            print "\t" + str(user_cnt) + ". " + subject_info['cc_number'][2:] + " - " + subject_info['complete_name']
            user_cnt+=1
        # await for user choice, returns if user enters nothing as the uuid
        destination_uuid = None
        user_number = 0
        while not (1 <= int(user_number) <= len(user_list)):
            user_number = raw_input("Please insert the number of the user: ")
            user = user_list[int(user_number) - 1]
        # asks for the message to be sent
        message = raw_input('Please insert your message: ')
        # creates signature with signature key and encodes message
        signature = self.card_utils.sign(text=message, key_type='AUTHENTICATION')
        base64_message = base64.b64encode(message)
        # message copy is encrypted with public key and encodes copy
        copy = rsa.encrypt(message=base64_message, pub_key=self.client_info['public_key'])
        base64_copy = base64.b64encode(copy)
        # encrypting message with server public key and encodes encrypted message
        dst_public_key = rsa.PublicKey.load_pkcs1(keyfile=user['personal_public_key'], format='PEM')
        encrypted_message = rsa.encrypt(message=base64_message, pub_key=dst_public_key)
        base64_encrypted_message = base64.b64encode(encrypted_message)
        # creates dict with info
        msg = {'message': base64_encrypted_message, 'signature': signature, 'certificate_dst': user['certificate']}
        # request for send
        result = self.request_send(source_uuid=self.client_info['user_uuid'],
                                   destination_uuid=user['user_uuid'],
                                   message=msg,
                                   copy=base64_copy)
        if result is None:
            print "Error in server request process"

    def request_new(self):
        """Sends request for new messages"""
        # message to send
        new_msg = {'type': 'new', 'uid': self.client_info['uid']}
        # send request
        return self.send_and_receive(message=new_msg)

    def request_receive(self, message_id):
        """Sends request for receive"""
        receive_msg = {'type': 'recv', 'uid': self.client_info['uid'], 'msg': message_id}
        # send request
        return self.send_and_receive(message=receive_msg)

    def request_receipt(self, message_id, receipt):
        """Sends request for receipt"""
        receipt_msg = {'type': 'receipt', 'uid': self.client_info['uid'], 'msg': message_id, 'receipt': receipt}
        # send request
        return self.send_and_receive(message=receipt_msg)

    def perform_new(self):
        """Sends request for new messages"""
        # request for user list
        result = self.request_new()
        if result is None:
            print "Error in server request process"
            return
        # new messages
        new_messages = result
        # no messages
        if not new_messages:
            print "There are no new messages."
            return
        # display messages
        print "New messages:"
        # message counter
        current_message = 1
        # print all message and associated counter
        for msg in new_messages:
            print "\t" + str(current_message) + ': ' \
                  + msg['complete_name'] + "(" + msg['cc_number'] + ") " + msg['msg_id'][37:]
            current_message += 1
        # await for user choice, returns if user enters nothing as the message number
        message_number = 0
        while not (1 <= message_number <= len(new_messages)):
            message_number = raw_input("Choose message you want to read: ")
            if not message_number:
                return
            try:
                message_number = int(message_number)
            except ValueError:
                print 'Not a number'
                continue
        # get message
        msg_id = new_messages[message_number - 1]['msg_id']
        # request for receive
        result = self.request_receive(message_id=msg_id)
        result = json.loads(result)
        if result is None:
            print "Error in server request process"
            return
        # decrypt and decode
        crypto_message = base64.b64decode(result['message'])
        base64_message = rsa.decrypt(crypto=crypto_message, priv_key=self.client_info['private_key'])
        message = base64.b64decode(base64_message)
        # verify signature and chain
        verification = self.card_utils.verify_signature(certificate_pem=result['certificate_dst'],
                                                        signature=result['signature'],
                                                        text=message)
        verification_text = "ok" if verification else "fail"
        certificate_chain = self.card_utils.verify_certificate_chain(certificate_pem=result['certificate_dst'])
        certificate_chain_text = "valid" if certificate_chain else "invalid"
        # get sender info
        sender_info = self.card_utils.get_certificate_subject_info(certificate_pem=result['certificate_dst'])
        # print contents and verifications
        print "%s %s %s:" % (sender_info['cc_number'], sender_info['complete_name'], msg_id[37:])
        print "\n\t%s" % message
        print "\n\tVerify: %s\n\tChain: %s" % (verification_text, certificate_chain_text)

        unsigned = {'msg_id': msg_id, 'message': message}
        unsigned = json.dumps(unsigned)
        unsigned = json.loads(unsigned)
        # receipt format
        signature = self.card_utils.sign(text=str(unsigned), key_type='AUTHENTICATION')
        # add read flag to msg_id
        msg_id = "_" + msg_id
        certificates = self.card_utils.get_citizen_certificates()
        for certificate in certificates:
            if certificate['TYPE'] in {'CITIZEN AUTHENTICATION CERTIFICATE'}:
                cert = certificate['CERTIFICATE_PEM']
        # get sender signature and certificate
        receipt_sec = {'signature': signature,
                           'certificate': cert}
        # request for receipt
        self.request_receipt(message_id=msg_id, receipt=receipt_sec)

    def request_all(self):
        """Sends request for all messages list"""
        # message to send
        all_msg = {'type': 'all', 'uid': self.client_info['uid']}
        # send request
        return self.send_and_receive(message=all_msg)

    def perform_all(self):
        """Shows list of messages sent and received"""
        # request for all
        result = self.request_all()
        if result is None:
            print "Error in server request process"
            return
        # message list
        if not result['received'] and not result['sent']:
            # no messages
            print "There are no messages."
        else:
            # display messages
            print "Received message list:"
            for msg in result['received']:
                print "\t" + msg['complete_name'] + "(" + msg['cc_number'] + ") " + msg['msg_id'][37:]
            print "Sent message list:"
            for msg in result['sent']:
                print "\t" + msg['complete_name'] + "(" + msg['cc_number'] + ") " + msg['msg_id'][37:]

    def request_status(self, message_id):
        """Sends request for status"""
        status_msg = {'type': 'status', 'uid': self.client_info['uid'], 'msg': message_id}
        # send request
        return self.send_and_receive(message=status_msg)

    def perform_status(self):
        """Sends request for status"""
        # request for all
        result = self.request_all()
        if result is None:
            print "Error in server request process"
            return
        # message list
        message_list = result
        if not message_list['sent']:
            # no messages
            print "There are no messages."
            return
        # message counter
        current_message = 1
        # display sent messages
        print( str(len(message_list['sent'])))
        print "Sent message list:"
        for msg in message_list['sent']:
            print "\t" + str(current_message) + ': ' \
                  + msg['complete_name'] + "(" + msg['cc_number'] + ") " + msg['msg_id'][37:]
            current_message += 1
        # await for user choice, returns if user enters nothing as the message number
        message_number = 0
        while not (1 <= message_number <= len(message_list['sent'])):
            message_number = raw_input("Choose message you want to read: ")
            if not message_number:
                return
            try:
                message_number = int(message_number)
            except ValueError:
                print 'Not a number'
                continue
        # get message

        msg_id = message_list['sent'][message_number-1]['msg_id']
        # request for status
        result = self.request_status(message_id=msg_id)

        if result is None:
            print "Error in server request process"
            return
        # decrypt and decode
        crypto_copy = base64.b64decode(result['msg'])
        base64_copy = rsa.decrypt(crypto=crypto_copy, priv_key=self.client_info['private_key'])
        copy = base64.b64decode(base64_copy)
        # show copys
        print "\nMessage sent:\n\t%s\nReceipts:" % copy
        # receipts
        for receipt in result['receipts']:
            signature_info = {'msg_id': msg_id, 'message': copy}
            signature_info = json.dumps(signature_info)
            signature_info = json.loads(signature_info)
            # verify signature and chain
            receipt['receipt'] = json.loads(receipt['receipt'])
            verification = self.card_utils.verify_signature(certificate_pem=receipt['receipt']['certificate'],
                                                            signature=receipt['receipt']['signature'],
                                                            text=str(signature_info))
            verification_text = "ok" if verification else "fail"
            certificate_chain = self.card_utils.verify_certificate_chain(certificate_pem=receipt['receipt']['certificate'])
            certificate_chain_text = "valid" if certificate_chain else "invalid"
            # get sender info
            sender_info = self.card_utils.get_certificate_subject_info(certificate_pem=receipt['receipt']['certificate'])
            # print contents and verifications
            print "\tDestination Info: %s %s" % (sender_info['cc_number'], sender_info['complete_name'])
            print "\n\tRead at: %s" % (datetime.datetime.fromtimestamp(float(receipt['date'])/1000).strftime('%c'))
            print "\n\tVerify: %s\n\tChain: %s" % (verification_text, certificate_chain_text)


if __name__ == "__main__":
    client_debug = False
    host = 8080
    # socket start
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to remote host
    try:
        sock.connect(("localhost", host))
    except Exception as e:
        if client_debug:
            print e
        sys.exit("Not able to connect to host: " + str(host))
    # client init
    client = Client(buffer_size=(512 * 1024), terminator="\r\n\n", debug=client_debug)
    # retrieve client
    client.client_info = client.create_retrieve_client()
    # create connection to server
    client.perform_create()
    # show menu
    client.client_menu()
