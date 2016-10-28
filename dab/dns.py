import socket
import asyncio
import aiodns
import ipaddress


class DNS:

    def __init__(self, nameservers=None):
        self.resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop(), nameservers=nameservers)

    async def lookup(self, address):
        try:
            ip = None
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                # Resolve the domain name
                result = await self.resolver.query(address, 'A')
                ip = ipaddress.ip_address(result[0].host)

            lookup = self.get_lookup(ip)
            result = await self.resolver.query(lookup, 'PTR')
            return [result.name]
        except aiodns.error.DNSError:
            return self.do_fallback(ip or address)

    def do_fallback(self, ip):
        try:
            # Fallback to the synchronous method that also inclused /etc/hosts or
            # other local configurations
            hostname, _, _ = socket.gethostbyaddr(str(ip))
            return [hostname]
        except (socket.herror, socket.gaierror):
            return []

    def get_lookup(self, ip):
        reverse_ip = ".".join(str(ip).split(".")[::-1])
        return reverse_ip + ".in-addr.arpa"
