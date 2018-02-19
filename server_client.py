import json
import sys

from utils_security import *
from log import *

TERMINATOR = "\r\n\n"
MAX_BUFSIZE = 64 * 1024

sys.tracebacklimit = 30


class Client:
    """Server client proxy"""
    count = 0
    
    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.connection_aes = None
        self.msg_counter = 0

    def __str__(self):
        """Converts object into string."""
        return "Client(addr:%s)" % (str(self.addr))

    """
    def asDict(self):
        returns client as dict
        return {'id': self.id}
    """

    def parseReqs(self, data):
        """
        Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket.
        """

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d" %
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = data.split(TERMINATOR)
        self.bufin = reqs[:-1]
        return reqs

    def sendResult(self, obj):
        """Send an object to this client."""
        try:
            if self.connection_aes is None:
                self.bufout += json.dumps(obj) + TERMINATOR
            else:
                self.bufout += self.connection_aes.encrypt(json.dumps(obj)) + TERMINATOR
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)" % self)

    def close(self):
        """
        Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        log(logging.INFO, "Client.close(%s)" % self)
        try:
            self.socket.close()
        except:
            logging.exception("Client.close(%s)" % self)
