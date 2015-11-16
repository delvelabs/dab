"""
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

import os
import re
import socket
import tempfile
import asyncio

from .netbios import NetBIOS


class Fingerprint:

    def __init__(self, type, value):
        self.type = type
        self.value = value

    def __repr__(self):
        return "%(type)-15s %(value)s" % self.__dict__


class Dab:

    # SSH PORTS
    SSH_PORTS = [22]

    # TLS-enabled Ports
    TLS_PORTS = [443, 5002] 

    def __init__(self, address):
        self.address = address
        self.fingerprints = []

    
    def add_fingerprint(self, type, value):
        if value:  # Skip empty values from the result
            type = re.sub(r'[^\w+]', '_', type).lower()
            self.fingerprints.append(Fingerprint(type=type, value=value))


    @asyncio.coroutine
    def fingerprint(self):
        try:
            # FIXME : No asyncio equivalent?
            hostname, _, _ = socket.gethostbyaddr(self.address)
            self.add_fingerprint("hostname", hostname)
        except:
            pass

        client = yield from self._nbt_hostscan()

        yield from self._apply_on_open_ports(self.SSH_PORTS, self._ssh_keyscan)
        yield from self._apply_on_open_ports(self.TLS_PORTS, self._ssl_fingerprint)
        yield from self._nbt_read_response(client)


    @asyncio.coroutine
    def _apply_on_open_ports(self, ports, callback):
        for port in ports:
            is_open = yield from self.is_open(port)
            if is_open:
                yield from callback(port)

    @asyncio.coroutine
    def _ssh_keyscan(self, port):
        try:
            fp = tempfile.NamedTemporaryFile(delete=False)

            command = ['ssh-keyscan', "-p", str(port), self.address]
            proc = yield from asyncio.create_subprocess_exec(*command, stdout=fp, stderr=asyncio.subprocess.DEVNULL)
            yield from proc.wait()
            fp.close()

            command = ["ssh-keygen", "-E", "sha256", "-l", "-f", fp.name]
            proc = yield from asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            keyscan_out = yield from proc.stdout.read()
            yield from proc.wait()

            keyscan_out = keyscan_out.decode('utf8').strip('\n')
            entries = keyscan_out.split('\n')
            for entry in entries:
                bytecount, hash, address, type = entry.split(' ')
                self.add_fingerprint("%s_%s" % (type.strip('()'), bytecount), hash)

        finally:
            os.remove(fp.name)

    @asyncio.coroutine
    def _ssl_fingerprint(self, port):
        try:
            fp = tempfile.NamedTemporaryFile(delete=False)

            command = ['openssl', 's_client', '-connect', self.address + ':' + str(port)]
            process = yield from asyncio.create_subprocess_exec(*command, stdout=fp, stdin=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            process.stdin.write(b'exit\n')
            yield from process.wait()
            fp.close()

            command = ['openssl', 'x509', '-fingerprint', '-noout', '-in', fp.name]
            process = yield from asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            output = yield from process.stdout.read()
            yield from process.wait()

            fingerprint = output.decode('utf-8')
            if fingerprint:
                fingerprint = fingerprint.strip('\n')
                self.add_fingerprint("ssl", fingerprint.split('=')[1])
        finally:
            os.remove(fp.name)

    @asyncio.coroutine
    def _nbt_hostscan(self):
        client = NetBIOS()
        yield from client.perform_request(self.address)
        return client

    @asyncio.coroutine
    def _nbt_read_response(self, client):
        nbt_name = yield from client.obtain_name(timeout=1)
        if nbt_name and len(nbt_name) > 0:
            self.add_fingerprint('nbt_hostname', nbt_name[0])
        
    @asyncio.coroutine
    def is_open(self, port):
        try:
            future = asyncio.open_connection(self.address, port)
            reader, writer = yield from asyncio.wait_for(future, timeout=0.5)
            writer.close()

            return True
        except:
            return False

