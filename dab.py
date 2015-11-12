#!/usr/bin/env python3
# Dab, a host fingerprint generator
# Delve Labs inc. 2015.

import argparse
import socket
import ssl
import sys
import subprocess

from nmb import NetBIOS
from subprocess import check_output




# SSH PORTS
SSH_PORTS = [22]

# TLS-enabled Ports
TLS_PORTS = [443, 5002] 

# NBT ports
NBT_PORTS = [139, 445]

# Results hashes
results = {'hostname' : '',
           'ssh_fingerprints' : [],
           'ssl_fingerprints' : [],
           'nbt_hostname' : ''}

parser = argparse.ArgumentParser(description='Get a host fingerprint')
parser.add_argument('host', metavar='target_host', type=str, nargs='?',
                   help='a target host')

args = parser.parse_args()
if len(sys.argv) <= 1:
    parser.print_help()
    sys.exit()


def is_open(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((args.host, port))
        s.close()
        return True
    except:
        return False

def list_open(ports):
    return [p for p in ports if is_open(p)]

# Hash Confidence level:i
# 1- TLS host fingerprint (preferred)
# 2- Hostnamei hash
# 3- All port checksum

# Get hostname
try:
    hostname,_,_ = socket.gethostbyaddr(args.host)
except:
    hostname = ''

results['hostname'] = hostname

for port in list_open(SSH_PORTS):
    keyscan_out = check_output(['ssh-keyscan', args.host], stderr=subprocess.PIPE).decode('utf-8')
    # Strip ending \n
    keyscan_out = keyscan_out.strip('\n')
    entries = keyscan_out.split('\n')
    for entry in entries:
        ip, htype, b64hash = entry.split(' ')
        results['ssh_fingerprints'].append({'type': htype, 'hash': b64hash})


for port in list_open(TLS_PORTS):
    # Try to get a TLS fingerprint then exit 
    process = subprocess.Popen(['openssl', 's_client', '-connect', args.host + ':' + str(port)],stdout=subprocess.PIPE,stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdin.write(b'Q\n')
    raw_cert = process.communicate()[0]
    process = subprocess.Popen(['openssl', 'x509', '-fingerprint', '-noout', '-in', '/dev/stdin'],stdout=subprocess.PIPE,stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdin.write(raw_cert)
    fingerprint = process.communicate()[0].decode('utf-8')
    if fingerprint:
        fingerprint = fingerprint.strip('\n')
        results['ssl_fingerprints'].append(fingerprint.split('=')[1])


for port in list_open(NBT_PORTS):
    client = NetBIOS.NetBIOS()
    nbt_name = client.queryIPForName(args.host, timeout=5)
    if len(nbt_name) > 0:
        results['nbt_hostname'] = nbt_name[0]

print(repr(results))
