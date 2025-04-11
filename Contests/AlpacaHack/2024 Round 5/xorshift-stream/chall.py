import os
import secrets
from Crypto.Util.strxor import strxor

class XorshiftStream:
    def __init__(self, key: int):
        self.state = key % 2**64

    def _next(self):
        self.state = (self.state ^ (self.state << 13)) % 2**64
        self.state = (self.state ^ (self.state >> 7)) % 2**64
        self.state = (self.state ^ (self.state << 17)) % 2**64
        return self.state

    def encrypt(self, data: bytes):
        ct = b""
        for i in range(0, len(data), 8):
            pt_block = data[i : i + 8]
            ct += (int.from_bytes(pt_block, "little") ^ self._next()).to_bytes(
                8, "little"
            )[: len(pt_block)]
        return ct

FLAG = os.environ.get("FLAG", "fakeflag").encode()

xss = XorshiftStream(secrets.randbelow(2**64))
key = secrets.token_bytes(len(FLAG))

c = xss.encrypt(key.hex().encode() + strxor(key, FLAG))
print(c.hex())
