import socket
import asyncio
import aiodns
import ipaddress
from async_timeout import timeout


class DNS:

    def __init__(self, nameservers=None, timeout=5.0):
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop, nameservers=nameservers)
        self.timeout = timeout

    async def lookup(self, address):
        try:
            ip = None
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                # Resolve the domain name
                result = await self._query(address, 'A')
                ip = ipaddress.ip_address(result[0].host)

            lookup = self.get_lookup(ip)
            result = await self._query(lookup, 'PTR')
            return self._all_hostnames(result.name, result.aliases)
        except asyncio.TimeoutError:
            return await self.loop.run_in_executor(None, self.do_fallback, ip or address)
        except aiodns.error.DNSError:
            return await self.loop.run_in_executor(None, self.do_fallback, ip or address)

    def do_fallback(self, ip):
        try:
            # Fallback to the synchronous method that also inclused /etc/hosts or
            # other local configurations
            hostname, aliases, _ = socket.gethostbyaddr(str(ip))
            return self._all_hostnames(hostname, aliases)
        except (socket.herror, socket.gaierror):
            return []

    def _all_hostnames(self, name, aliases):
        return list({name} | set(aliases))

    def get_lookup(self, ip):
        reverse_ip = ".".join(str(ip).split(".")[::-1])
        return reverse_ip + ".in-addr.arpa"

    async def _query(self, address, record):
        async with timeout(self.timeout):
            return await self.resolver.query(address, record)
