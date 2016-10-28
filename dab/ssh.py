import asyncio
import os
import tempfile


class SSH:

    async def keyscan(self, address, port):
        try:
            fp = tempfile.NamedTemporaryFile(delete=False)

            command = ['ssh-keyscan', "-p", str(port), address]
            proc = await asyncio.create_subprocess_exec(*command, stdout=fp, stderr=asyncio.subprocess.DEVNULL)
            returncode = await proc.wait()
            fp.close()

            if returncode != 0:
                return []

            sha256 = await self.generate_fingerprint(["ssh-keygen", "-E", "sha256", "-l", "-f", fp.name])
            md5 = await self.generate_fingerprint(["ssh-keygen", "-E", "md5", "-l", "-f", fp.name])
            combined = sha256 + md5
            if combined:
                return combined

            default = await self.generate_fingerprint(["ssh-keygen", "-l", "-f", fp.name])
            return default

        finally:
            os.remove(fp.name)

    async def generate_fingerprint(self, command):
        proc = await asyncio.create_subprocess_exec(*command,
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.DEVNULL)
        keyscan_out = await proc.stdout.read()
        returncode = await proc.wait()

        if not keyscan_out:
            return []

        if returncode != 0:
            return []

        rv = []
        keyscan_out = keyscan_out.decode('utf8').strip('\n')

        entries = keyscan_out.split('\n')
        for entry in entries:
            parts = entry.split(' ')
            if len(parts) != 4:
                continue  # Not a standard output, ignore

            bytecount, full_hash, address, type = parts
            if full_hash.startswith("MD5:"):
                hash_type, hash = "md5", full_hash[4:]
            elif full_hash.startswith("SHA256:"):
                hash_type, hash = "sha256", full_hash[7:]
            else:
                hash_type, hash = "md5", full_hash
            rv.append(("ssh_%s_%s_%s" % (type.strip('()'), bytecount, hash_type), hash))

        return rv
