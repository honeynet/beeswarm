import logging

from gevent.server import DatagramServer
from beeswarm.shared.models.protocol_type import ProtocolType
from beeswarm.drones.honeypot.capabilities.handlerbase import HandlerBase


logger = logging.getLogger(__name__)


class Sip(HandlerBase, DatagramServer):

    def __init__(self, sessions, options, workdir):
        super(Sip, self).__init__(sessions, options, workdir)
        self.protocol_type = ProtocolType.UDP
        self.socket = None

    def handle_session(self, data, address):
        assert self.socket
        print 'Received UDP from {0}: {1}'.format(address, data)
        self.socket.sendto('Hello Chris, this is Beeswarm honeypot talking to ye!', address)


