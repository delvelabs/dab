"""

This code was originally extracted from pysmb and was adapted for asyncio.

Copyright (C) 2001-2015 Michael Teo <miketeo (a) miketeo.net>
Copyright (C) 2015-     Delve Labs inc. <info@delvelabs.ca>

This software is provided 'as-is', without any express or implied warranty.
In no event will the author be held liable for any damages arising from the
use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.

3. This notice cannot be removed or altered from any source distribution.

"""
import asyncio
import re
import random
import struct
import string
import time
import socket


class NetBIOS:


    def __init__(self, protocol=None):
        """
        Instantiate a NetBIOS instance, and creates a IPv4 UDP socket to listen/send NBNS packets.

        :param boolean broadcast: A boolean flag to indicate if we should setup the listening UDP port in broadcast mode
        :param integer listen_port: Specifies the UDP port number to bind to for listening. If zero, OS will automatically select a free port number.
        """
        self.trn_id = random.randint(1, 0xFFFF)
        self.transport = None
        self.protocol = None

        self.request_date = None

    @asyncio.coroutine
    def perform_request(self, ip, port=137):
        if not self.protocol:
            self.transport, self.protocol = yield from create_connection()

        self.protocol.send_request(self.trn_id, ip, port)
        self.request_date = time.time()

    def close(self):
        """
        Close the underlying and free resources.

        The NetBIOS instance should not be used to perform any operations after this method returns.

        :return: None
        """
        if self.transport:
            # Let the protocol be re-used
            self.transport.close()
            self.sock = None
            self.transport = None
            self.protocol = None


    @asyncio.coroutine
    def obtain_name(self, timeout=30):
        since_request = time.time() - self.request_date
        if since_request < timeout:
            yield from asyncio.sleep(timeout - since_request)

        return self.protocol.get_name(self.trn_id)


class NetBiosProtocol:

    TYPE_SERVER = 0x20
    HEADER_STRUCT_FORMAT = '>HHHHHH'
    HEADER_STRUCT_SIZE = struct.calcsize(HEADER_STRUCT_FORMAT)

    def __init__(self):
        self.requests = {}
        self.transport = None

    def get_name(self, id):
        return self.requests.pop(id, None)

    def connection_made(self, transport):
        self.transport = transport


    def datagram_received(self, data, addr):
        if len(data) == 0:
            raise NotConnectedError

        trn_id, ret = self._decode_ip_query_packet(data)

        out = [s[0] for s in ret if s[1] == self.TYPE_SERVER]
        if trn_id in self.requests:
            self.requests[trn_id] = out


    def send_request(self, id, ip, port):
        self.requests[id] = None
        data = self._prepare_net_name_query(id, False)
        self.transport.sendto(data, (ip, port))


    def _prepare_net_name_query(self, trn_id, is_broadcast=True):
        #
        # Contributed by Jason Anderson
        #
        header = struct.pack(self.HEADER_STRUCT_FORMAT,
                             trn_id, (is_broadcast and 0x0010) or 0x0000, 1, 0, 0, 0)
        payload = self._encode_name('*', 0) + b'\x00\x21\x00\x01'

        return header + payload

    def _encode_name(self, name, type, scope=None):
        #
        # Contributed by Jason Anderson
        #
        """
        Perform first and second level encoding of name as specified in RFC 1001 (Section 4)
        """
        if name == '*':
            name = name + '\0' * 15
        else:
            name = name[:15].ljust(15) + chr(type)

        def _do_first_level_encoding(m):
            s = ord(m.group(0))
            return string.ascii_uppercase[s >> 4] + string.ascii_uppercase[s & 0x0f]

        encoded_name = chr(len(name) * 2) + re.sub('.', _do_first_level_encoding, name)
        if scope:
            encoded_scope = ''
            for s in string.split(scope, '.'):
                encoded_scope = encoded_scope + chr(len(s)) + s
            return bytes(encoded_name + encoded_scope + '\0', 'ascii')
        else:
            return bytes(encoded_name + '\0', 'ascii')


    def _decode_ip_query_packet(self, data):
        if len(data) < self.HEADER_STRUCT_SIZE:
            raise Exception

        trn_id, code, question_count, answer_count, authority_count, additional_count = \
            struct.unpack(self.HEADER_STRUCT_FORMAT, data[:self.HEADER_STRUCT_SIZE])

        is_response = bool((code >> 15) & 0x01)
        opcode = (code >> 11) & 0x0F
        flags = (code >> 4) & 0x7F
        rcode = code & 0x0F
        numnames = data[self.HEADER_STRUCT_SIZE + 44]

        if numnames > 0:
            ret = []
            offset = self.HEADER_STRUCT_SIZE + 45

            for i in range(0, numnames):
                mynme = data[offset:offset + 15]
                mynme = mynme.strip()
                ret.append((str(mynme, 'ascii'), data[offset+15]))
                offset += 18

            return trn_id, ret
        else:
            return trn_id, None


@asyncio.coroutine
def create_connection():
    loop = asyncio.get_event_loop()
    # One protocol instance will be created to serve all client requests
    transport, protocol = yield from loop.create_datagram_endpoint(
        NetBiosProtocol, local_addr=("0.0.0.0", 0), family=socket.AF_INET)

    sock = transport.get_extra_info('socket')
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    return transport, protocol
