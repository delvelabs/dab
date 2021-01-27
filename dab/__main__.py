#!/usr/bin/env python3
"""
Dab, a host fingerprint generator

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
import argparse

from dab import Dab
from dab.dns import DNS


def main():
    parser = argparse.ArgumentParser(description='Get a host fingerprint')
    parser.add_argument('--nameservers', metavar='nameservers', type=lambda x: x.split(','),
                        help="Comma-separted list of nameservers to use in resolution")
    parser.add_argument('host', metavar='target_host', type=str, nargs='?',
                        help='a target host')

    args = parser.parse_args()
    if not args.host:
        parser.print_help()
        raise SystemExit()

    loop = asyncio.get_event_loop()
    dab = Dab(args.host, dns_client=DNS(nameservers=args.nameservers or None))
    loop.run_until_complete(dab.fingerprint())
    loop.close()

    for f in sorted(dab.fingerprints):
        print(f)


if __name__ == '__main__':
    main()
