#!/usr/bin/env python3
# Dab, a host fingerprint generator
# Delve Labs inc. 2015.

import asyncio
import argparse
import sys

from subprocess import check_output
from dab import Dab

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
    loop.close()

    for f in dab.fingerprints:
        print(f)
