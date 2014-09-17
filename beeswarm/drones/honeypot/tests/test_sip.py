# Copyright (C) 2014 Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import shutil
import tempfile
import os
import socket

import gevent
from gevent.socket import socket as gevent_socket
from gevent.server import DatagramServer

from beeswarm.drones.honeypot.honeypot import Honeypot
from beeswarm.drones.honeypot.capabilities.sip import Sip


class SipTests(unittest.TestCase):
    def setUp(self):
        self.work_dir = tempfile.mkdtemp()
        Honeypot.prepare_environment(self.work_dir)

    def tearDown(self):
        if os.path.isdir(self.work_dir):
            shutil.rmtree(self.work_dir)

    def test_sip_regsiter(self):
        # basic options for the sip capability
        sessions = {}
        options = {'port': 5060, 'protocol_specific_data': {}, 'users': {}}
        sut = Sip(sessions, options, self.work_dir)

        # fire up the SIP capability datagram server
        server = DatagramServer(('0.0.0.0', 0), sut.handle_session)
        server.start()
        sut.socket = server.socket._sock

        address = ('localhost', server.server_port)
        sock = gevent_socket(type=socket.SOCK_DGRAM)
        sock.settimeout(200)
        sock.connect(address)
        register_message = """REGISTER sip:192.168.1.1 SIP/2.0\r\n
Via: SIP/2.0/UDP 172.16.2.1:56084;rport;branch=z9h94bKPjqlaaT-qxoK2GrLXDJwVkQBpQehxCcLpl\r\n
Max-Forwards: 70\r\n
From: "7025551212" <sip:7025551212@192.168.1.1>;tag=1zBbx.zO8JNk3eNqErV8jGJKcJ6U4DY4\r\n
To: "7025551212" <sip:7025551212@192.168.1.1>\r\n
Call-ID: 420R4aNI9v26yzQ5u7t9nyM0YVj9mEjM\r\n
CSeq: 1234 REGISTER\r\n
User-Agent: Bria iOS 3.1.1\r\n
Supported: outbound, path\r\n
Contact: "7025551212" <sip:7025551212@172.16.2.1:56084;ob>;reg-id=1;+sip.instance="<urn:uuid:11111111-1111-1111-1111-111111111111>"\r\n
Expires: 3600\r\n
Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n
Content-Length:  0\r\n\r\n"""
        sock.send(register_message)
        received_data = sock.recv(4096)

        # TODO: down the road, we should have quite a few more asserts on the reply
        self.assertTrue(received_data.startswith('SIP/2.0 404 Not found'))
