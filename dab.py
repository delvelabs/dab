#!/usr/bin/env python3
# Dab, a host fingerprint generator
# Delve Labs inc. 2015.

import asyncio
import re
import argparse
import socket
import ssl
import sys
import subprocess

from nmb import NetBIOS
from subprocess import check_output


class Dab:

    # SSH PORTS
    SSH_PORTS = [22]

    # TLS-enabled Ports
    TLS_PORTS = [443, 5002] 

    # NBT ports
    NBT_PORTS = [139, 445]


    def __init__(self, address):
        self.address = address
        self.fingerprints = []

    
    def add_fingerprint(self, type, value):
        if value:  # Skip empty values from the result
            type = re.sub(r'[^\w+]', '_', type).lower()
            self.fingerprints.append(dict(type=type, value=value))


    @asyncio.coroutine
    def fingerprint(self):
        try:
            # FIXME : No asyncio equivalent?
            hostname, _, _ = socket.gethostbyaddr(self.address)
            self.add_fingerprint("hostname", hostname)
        except:
            pass

        yield from self._apply_on_open_ports(self.SSH_PORTS, self._ssh_keyscan)
        yield from self._apply_on_open_ports(self.TLS_PORTS, self._ssl_fingerprint)


    @asyncio.coroutine
    def _apply_on_open_ports(self, ports, callback):
        for port in ports:
            is_open = yield from self.is_open(port)
            if is_open:
                yield from callback(port)

    @asyncio.coroutine
    def _ssh_keyscan(self, port):
        keyscan_out = check_output(['ssh-keyscan', "-p", str(port), self.address], stderr=subprocess.PIPE).decode('utf-8')
        # Strip ending \n
        keyscan_out = keyscan_out.strip('\n')
        entries = keyscan_out.split('\n')
        for entry in entries:
            ip, htype, b64hash = entry.split(' ')
            self.add_fingerprint(htype, b64hash)

    @asyncio.coroutine
    def _ssl_fingerprint(self, port):
        process = subprocess.Popen(['openssl', 's_client', '-connect', self.address + ':' + str(port)], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdin.write(b'exit\n')
        raw_cert = process.communicate()[0]
        process = subprocess.Popen(['openssl', 'x509', '-fingerprint', '-noout', '-in', '/dev/stdin'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdin.write(raw_cert)
        fingerprint = process.communicate()[0].decode('utf-8')
        if fingerprint:
            fingerprint = fingerprint.strip('\n')
            self.add_fingerprint("ssl", fingerprint.split('=')[1])

    @asyncio.coroutine
    def _nbt_hostscan(self, port):
        client = NetBIOS.NetBIOS()
        nbt_name = client.queryIPForName(self.address, timeout=1)
        if len(nbt_name) > 0:
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



# Hash Confidence level:
# 1- TLS host fingerprint (preferred)
# 2- Hostname hash
# 3- All port checksum

# Get hostname



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get a host fingerprint')
    parser.add_argument('host', metavar='target_host', type=str, nargs='?',
                        help='a target host')

    args = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        raise SystemExit()

    loop = asyncio.get_event_loop()
    dab = Dab(args.host)
    loop.run_until_complete(dab.fingerprint())
    print(dab.fingerprints)

raise SystemExit()
