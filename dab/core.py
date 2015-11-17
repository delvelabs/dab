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
import tempfile
import asyncio

from .netbios import NetBIOS
from .dns import DNS
from .ssh import SSH



class Fingerprint:

    def __init__(self, type, value):
        self.type = type
        self.value = value

    def __repr__(self):
        return "%(type)-25s %(value)s" % self.__dict__

    def __hash__(self):
        return hash((self.type, self.value))

    def __eq__(self, other):
        return self.type == other.type and self.value == other.value

    def __lt__(self, other):
        return (self.type, self.value) < (other.type, other.value)


class Dab:

    # SSH PORTS
    SSH_PORTS = [22]

    # TLS-enabled Ports
    TLS_PORTS = [443, 5002] 

    def __init__(self, address, netbios_client=None, dns_client=None, ssh_client=None):
        self.address = address
        self.fingerprints = set()
        self.netbios_client = netbios_client or NetBIOS()
        self.dns_client = dns_client or DNS()
        self.ssh_client = ssh_client or SSH()

    
    def add_fingerprint(self, type, value):
        if value:  # Skip empty values from the result
            type = re.sub(r'[^\w+]', '_', type).lower()
            self.fingerprints.add(Fingerprint(type=type, value=value))


    @asyncio.coroutine
    def fingerprint(self):
        # Perform all checks concurrently
        results = yield from asyncio.gather(
            self.dns_client.lookup(self.address),
            self._nbt_hostscan(),
            self._apply_on_open_ports(self.SSH_PORTS, lambda port: self.ssh_client.keyscan(self.address, port)),
            self._apply_on_open_ports(self.TLS_PORTS, self._ssl_fingerprint)
        )

        for hostname in results[0]:
            self.add_fingerprint("hostname", hostname)
        for type, hash in results[2]:
            self.add_fingerprint(type, hash)

        # Response arrives after specified timeout
        yield from self._nbt_read_response()


    @asyncio.coroutine
    def _apply_on_open_ports(self, ports, callback):
        rv = []
        for port in ports:
            is_open = yield from self.is_open(port)
            if is_open:
                result = yield from callback(port)
                if result:
                    rv = rv + result
        
        return rv

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
        yield from self.netbios_client.perform_request(self.address)

    @asyncio.coroutine
    def _nbt_read_response(self):
        nbt_name = yield from self.netbios_client.obtain_name(self.address, timeout=1)
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

