import asyncio
import os
import tempfile


class SSH:
    
    @asyncio.coroutine
    def keyscan(self, address, port):
        try:
            fp = tempfile.NamedTemporaryFile(delete=False)

            command = ['ssh-keyscan', "-p", str(port), address]
            proc = yield from asyncio.create_subprocess_exec(*command, stdout=fp, stderr=asyncio.subprocess.DEVNULL)
            yield from proc.wait()
            fp.close()

            sha256 = yield from self.generate_fingerprint(["ssh-keygen", "-E", "sha256", "-l", "-f", fp.name])
            md5 = yield from self.generate_fingerprint(["ssh-keygen", "-E", "md5", "-l", "-f", fp.name])
            combined = sha256 + md5
            if combined:
                return combined

            default = yield from self.generate_fingerprint(["ssh-keygen", "-l", "-f", fp.name])
            return default

        finally:
            os.remove(fp.name)

    def generate_fingerprint(self, command):
        proc = yield from asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        keyscan_out = yield from proc.stdout.read()
        yield from proc.wait()

        if not keyscan_out:
            return []

        rv = []
        keyscan_out = keyscan_out.decode('utf8').strip('\n')

        entries = keyscan_out.split('\n')
        for entry in entries:
            bytecount, full_hash, address, type = entry.split(' ')
            if full_hash.startswith("MD5:"):
                hash_type, hash = "md5", full_hash[4:]
            elif full_hash.startswith("SHA256:"):
                hash_type, hash = "sha256", full_hash[7:]
            else:
                hash_type, hash = "md5", full_hash
            rv.append(("ssh_%s_%s_%s" % (type.strip('()'), bytecount, hash_type), hash))

        return rv
