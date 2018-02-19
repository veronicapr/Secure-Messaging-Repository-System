import base64
import json
import logging
import os
import re
import sys
import time
import uuid

import rsa

from log import *
from utils_citizen_card import *

sys.tracebacklimit = 30

MBOXES_PATH = "mboxes"
RECEIPTS_PATH = "receipts"
DESC_FILENAME = "description"


class UserDescription(dict):
    """User information, contains the user info given upon creation."""

    def __init__(self, uid, description=None):
        dict.__init__(self, id=uid, description=description)
        self.id = uid
        self.description = description


class ServerRegistry:
    """Controls the entire server user and messages."""

    def __init__(self):
        """Creates the list of users from the already created message boxes."""
        self.card_utils = CitizenCardUtils()
        self.uid_counter = 1
        self.users = {}
        # create messages and receipts folder if they don't exist
        for dir_name in [MBOXES_PATH, RECEIPTS_PATH]:
            try:
                if not os.path.exists(dir_name):
                    logging.debug("Creating " + dir_name)
                    os.mkdir(dir_name)
            except:
                logging.exception("Cannot create directory " + dir_name)
                sys.exit(1)
        # for each entry on the message boxes
        for entry_name in os.listdir(MBOXES_PATH):
            log(logging.INFO, "Found " + entry_name)
            if os.path.isdir(os.path.join(MBOXES_PATH, entry_name)):
                # try create uuid from entry name
                try:
                    user_uuid = uuid.UUID('{' + entry_name + '}')
                except:
                    continue
                # user found confirmed, loading description
                log(logging.INFO, "Loading " + entry_name)
                path = os.path.join(MBOXES_PATH, entry_name, DESC_FILENAME)
                try:
                    with open(path) as f:
                        description = json.loads(f.read())
                except:
                    logging.exception("Cannot load user description from " + path)
                    sys.exit(1)
                # add existing user with next uid to registry users and increment uid
                self.users[str(user_uuid)] = UserDescription(self.uid_counter, description)
                self.uid_counter += 1

    def saveOnFile(self, path, data):
        """Saves new data to the corresponding path"""
        with open(path, "w") as f:
            f.write(data)

    def readFromFile(self, path):
        """Loads data from the corresponding path"""
        log(logging.DEBUG, "Read from file: " + path)
        with open(path, "r") as f:
            return f.read()

    def getUuidFromUid(self, uid):
        """Obtains user uuid from given uid"""
        for user in self.users.values():
            if user['id'] == uid:
                return str(user['description']['uuid'])
        return None

    def userExists(self, user_uuid):
        """Checks if user exists."""
        return self.getUser(user_uuid) is not None

    def getUser(self, user_uuid):
        """Returns user if he exists in the uuid list."""
        if user_uuid in self.users.keys():
            return self.users[user_uuid]
        else:
            return None

    def getVerifiedUser(self, user_uuid, description):
        """Returns user if he exists in the uuid list."""
        if user_uuid in self.users.keys():
            if self.users[user_uuid]['description']['data']['certificate'] == description['data']['certificate']:
                return self.users[user_uuid]
        else:
            return None

    def getUserPubKey(self, uuid):
        # Resturns the users personal public key
        for user in self.users.values():
            if str(user['description']['uuid']) == str(uuid):
                return user['description']['data']['personal_public_key']
        return None

    def getCert(self,uuid):
        # Resturns the user certificate
        for user in self.users.values():
            if user['id'] == uuid:
                return user['description']['data']['certificate']
        return None

    def addUser(self, description, user_uuid):
        """Adds new user to the server registry, by creating the corresponding message box"""
        # removes the request type in the description
        if 'type' in description.keys():
            del description['type']
        # add user debug log
        log(logging.DEBUG, "\"%s\": %s" % (user_uuid, description))
        # add new user with next uid to registry users and increment uid
        user = UserDescription(self.uid_counter, description)
        self.uid_counter += 1
        self.users[user_uuid] = user
        # creates corresponding message and receipt boxes
        for path in [self.userMessageBox(user_uuid), self.userReceiptBox(user_uuid)]:
            try:
                os.mkdir(path)
            except:
                logging.exception("Cannot create directory " + path)
                sys.exit(1)
        # create user description file in the corresponding message box
        try:
            path = os.path.join(MBOXES_PATH, user_uuid, DESC_FILENAME)
            log(logging.DEBUG, "Adding user description on " + path)
            self.saveOnFile(path, json.dumps(description))
        except:
            logging.exception("Cannot create description file")
            sys.exit(1)
        # if successful returns the user
        return user

    def listUsers(self, user_uuid):
        """Retrieves list of all users if given user_uuid is None else returns data for given user"""
        user_list = []
        if not user_uuid:
            log(logging.DEBUG, "Looking for all connected users")
            for user in self.users.keys():
                print("\n\n USER IS " + str(self.users[user]))
                user_info = {
                    'user_uuid' : user,
                    'certificate' : self.users[user]['description']['data']['certificate'],
                    'personal_public_key' : self.users[user]['description']['data']['personal_public_key']
                }
                user_list.append(user_info)
        else:
            log(logging.DEBUG, "Looking for \"%s\"" % user_uuid)
            user_list.append(self.getUser(user_uuid))
        return user_list

    def userMessageBox(self, user_uuid):
        """Returns the message box path for the user"""
        return os.path.join(MBOXES_PATH, str(user_uuid))

    def userReceiptBox(self, user_uuid):
        """Returns the receipt box path for the user"""
        return os.path.join(RECEIPTS_PATH, str(user_uuid))

    def sendMessage(self, src, dst, msg, receipt):
        """Sends message to the dst message box and creates a receipt of that message on the source receipt box"""
        # retrieves new message number
        num = self.newFile(self.userMessageBox(dst), src)
        # save to file on dst message box
        try:
            path = self.userMessageBox(dst)
            log(logging.INFO, "Saving message \"%s\" at \"%s\"" % (src + "_" + num, path))
            self.saveOnFile(os.path.join(path, src + "_" + num), json.dumps(msg))
            path = self.userReceiptBox(src)
            log(logging.INFO, "Saving message \"%s\" at \"%s\"" % (dst + "_" + num, path))
            self.saveOnFile(os.path.join(path, dst + "_" + num), receipt)
        except:
            logging.exception("Cannot create message or receipt file")
            return ["", ""]
        # returns created messages names
        return [src + "_" + num, dst + "_" + num]

    def newFile(self, folder_path, user_uuid):
        """Determines message number for new message"""
        # message number starts at 1
        msg_number = 1
        while True:
            # checks if either exists and unread or read message with current number, returns current number if not
            if os.path.exists(os.path.join(folder_path, user_uuid + "_" + str(msg_number))) or os.path.exists(os.path.join(folder_path, "_" + user_uuid + "_" + str(msg_number))):
                msg_number += 1
            else:
                return str(msg_number)

    def retrieveUserUuidFromMsgId(self, msg):
        msg_id_parts = str.split(str(msg), "_")
        # path for new file
        if len(msg_id_parts) == 2:
            return msg_id_parts[0]
        else:
            return msg_id_parts[1]

    def userAllMessages(self, uid):
        """Retrieves all read and unread messages from the user message box"""
        return self.userMessages(self.userMessageBox(self.getUuidFromUid(uid)), "_?([a-f]|[0-9]){8}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){12}_[0-9]+")

    def userSentMessages(self, uid):
        """Retrieves all sent messages from the user receipt box"""
        return self.userMessages(self.userReceiptBox(self.getUuidFromUid(uid)), "([a-f]|[0-9]){8}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){12}_[0-9]+")

    def userNewMessages(self, uid):
        """Retrieves all unread messages from the user message box"""
        return self.userMessages(self.userMessageBox(self.getUuidFromUid(uid)), "([a-f]|[0-9]){8}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){12}_[0-9]+")

    def userMessages(self, path, pattern):
        """Locates and retrieves all messages that correspond to the given pattern"""
        log(logging.DEBUG, "Look for files at " + path + " with pattern " + pattern)
        # if folder does not exist
        if not os.path.exists(path):
            return []
        # result message list
        message_list = []
        # retrieve file names
        try:
            for filename in os.listdir(path):
                log(logging.DEBUG, "\tFound file " + filename)
                # only adds if name has the corresponding pattern
                if re.match(pattern, filename):
                    message_list.append(filename)
        except:
            logging.exception("Error while listing messages in directory " + path)

        messages_to_send = []
        for msg_id in message_list:
            cert = self.users[self.retrieveUserUuidFromMsgId(msg_id)]['description']['data']['certificate']
            subject_info = self.card_utils.get_certificate_subject_info(certificate_pem=cert)
            messages_to_send.append({
                'cc_number' : subject_info['cc_number'],
                'complete_name' : subject_info['complete_name'],
                'msg_id' : msg_id
            })
        return messages_to_send

    def messageExists(self, uid, message):
        """Message already exists"""
        return os.path.exists(os.path.join(self.userMessageBox(uid), message))

    def recvMessage(self, uid, msg):
        """Updates name of message in receive box to read flag and returns message text"""
        result = []
        # try to find message patterns
        matches = re.match("_?([a-f]|[0-9]){8}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){12}_[0-9]+", msg)
        if not matches:
            log(logging.ERROR, "Internal error, wrong message file name format!")
            sys.exit(2)
        try:
            result = self.readMsgFile(uid, msg)
        except:
            logging.exception("Cannot read message " + msg + " from user " + uid)
        return result

    def readMsgFile(self, uid, msg):
        """Read message text and rename to read if not previously read"""
        # folder path
        path = self.userMessageBox(self.getUuidFromUid(uid))
        # rename situation
        if not msg.startswith('_'):
            # previous file path
            f = os.path.join(path, msg)
            # new path
            path = os.path.join(path, "_" + msg)
            try:
                # rename for message marking
                log(logging.DEBUG, "Marking message " + msg + " as read")
                os.rename(f, path)
            except:
                # returns no text if failed to rename
                logging.exception("Cannot rename message file to " + path)
                return ""
        else:
            path = os.path.join(path, msg)
        # return message text
        return self.readFromFile(path)

    def messageWasRead(self, uid, msg):
        """Determines if message starts with _ and adds _ to the start of the path in case it wasn't read"""
        if msg.startswith("_"):
            return os.path.exists(os.path.join(self.userMessageBox(uid), msg))
        else:
            return os.path.exists(os.path.join(self.userMessageBox(uid), "_" + msg))

    def storeReceipt(self, uid, msg, receipt):
        """Store receipt in msg dst user recipt box"""
        # check is message is read on user message box
        path = os.path.join(self.userMessageBox(self.getUuidFromUid(uid)), msg)
        log(logging.DEBUG, "Verifying read status of message " + msg + " on " + path)
        if not os.path.exists(path):
            log(logging.ERROR, "Message doesn't exist on user message box")
            return
        # try to find message patterns
        matches = re.match("_?([a-f]|[0-9]){8}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){12}_[0-9]+", msg)
        if not matches:
            log(logging.ERROR, "Internal error, wrong message file name format!")
            return
        # spilt by "_"
        msg_id_parts = str.split(str(msg), "_")
        log(logging.DEBUG, "Message to be stored parts: " + str(msg_id_parts))
        # path for new file
        if len(msg_id_parts) == 2:
            log(logging.ERROR, "Message not read")
            return
            # path = os.path.join(self.userReceiptBox(msg_id_parts[0]), "_%s_%s_%d" % (self.getUuidFromUid(uid), msg_id_parts[1], time.time() * 1000))
        else:
            path = os.path.join(self.userReceiptBox(msg_id_parts[1]), "_%s_%s_%d" % (self.getUuidFromUid(uid), msg_id_parts[2], time.time() * 1000))
        # save new file
        try:
            log(logging.INFO, "Saving receipt at " + path)
            self.saveOnFile(path, json.dumps(receipt))
        except:
            logging.exception("Cannot create receipt file")

    def copyExists(self, uid, message):
        """Check for message copy in the sent messages"""
        return os.path.exists(os.path.join(self.userReceiptBox(self.getUuidFromUid(uid)), message))

    def getReceipts(self, uid, msg):
        """Get corresponding receipts of the given message"""
        # try to find message patterns
        matches = re.match("_?([a-f]|[0-9]){8}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){4}-([a-f]|[0-9]){12}_[0-9]+", msg)
        if not matches:
            log(logging.ERROR, "Internal error, wrong message file name format!")
            sys.exit(2)
        # get user receipt box
        box_dir = self.userReceiptBox(self.getUuidFromUid(uid))
        # get message copy
        try:
            path = os.path.join(box_dir, msg)
            copy = self.readFromFile(path)
        except:
            logging.exception("Cannot read a copy file")
            copy = ""
        # format result message
        result = {"msg": copy, "receipts": []}
        # load all files in receipt bx
        for file_name in os.listdir(box_dir):
            msg_id_parts = str.split(file_name, "_")
            if len(msg_id_parts) == 4:
                if (msg_id_parts[1] + "_" + msg_id_parts[2]) == msg:
                    # get path for file
                    path = os.path.join(self.userReceiptBox(self.getUuidFromUid(uid)), file_name)
                    # read file
                    try:
                        log(logging.DEBUG, "Reading " + path)
                        receipt_text = self.readFromFile(path)
                    except:
                        logging.exception("Cannot read a receipt file")
                        receipt_text = ""
                    # store receipt in result to send
                    receipt = {"date": msg_id_parts[3], "id": msg_id_parts[1], "receipt": receipt_text}
                    result['receipts'].append(receipt)
                else:
                    continue
            else:
                continue
        # send result
        return result
