from hashlib import md5
import random
from Crypto.Util.number import long_to_bytes

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

class Feistel:
    def __init__(self, key: bytes, rounds=10, block_size=16) -> None:
        assert len(key) == block_size // 2
        assert block_size % 4 == 0
        self.rounds = rounds
        self.block_size = block_size
        self.S = list(range(256))
        random.shuffle(self.S)
        self._expand_key(key)
    
    @staticmethod
    def xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))
    
    @staticmethod
    def _pad(m: bytes, n: int) -> bytes:
        x = n - len(m) % n
        return m + bytes([x] * x)
    
    @staticmethod
    def _unpad(m: bytes, n: int) -> bytes:
        x = m[-1]
        if not 1 <= x <= n:
            raise ValueError("invalid padding")
        return m[:-x]
    
    def permutation(self, a: bytearray):
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)
        return a

    def sbox(self, x: bytearray):
        return bytearray(self.S[y] for y in x)

    def _expand_key(self, key: bytes) -> None:
        self._round_keys = []
        H = self._pad(key, self.block_size)
        empty = 0
        for i in range(self.rounds):
            self._round_keys.append(int.from_bytes(H[:4], "big"))
            
            if not empty:
                H = md5(H).digest()[:4]
            else:
                H = H[4:]
                if (len(H) == 0):
                    empty = 1
                    H = key

        assert len(self._round_keys) == self.rounds
    
    def _f(self, l: int, r: int, key: int) -> int:
        a = bytearray(int(r ^ key).to_bytes(4, "big"))
        return l ^ int.from_bytes(self.permutation(self.sbox(a)), "big")
    
    def _encrypt_block(self, pt: bytes) -> bytes:
        assert len(pt) == self.block_size
        blocks = [int.from_bytes(pt[(self.block_size // 4) * i : (self.block_size // 4)*(i + 1)], "big") for i in range(4)]

        for i in range(self.rounds):
            blocks[1] = self._f(blocks[1], blocks[0], self._round_keys[i])
            blocks = blocks[1:] + [blocks[0]]
        ct = bytearray() 
        for l in blocks:
            ct += l.to_bytes(self.block_size // 4, "big")
        return ct

    def _decrypt_block(self, ct: bytes) -> bytes:
        assert len(ct) == self.block_size
        blocks = [int.from_bytes(ct[(self.block_size // 4) * i : (self.block_size // 4)*(i + 1)], "big") for i in range(4)]

        for i in reversed(range(self.rounds)):
            blocks = [blocks[-1]] + blocks[:-1]
            blocks[1] = self._f(blocks[1], blocks[0], self._round_keys[i])
        pt = bytearray() 
        for l in blocks:
            pt += l.to_bytes(self.block_size // 4, "big")
        return pt
    
    def encrypt(self, pt: bytes) -> bytes:
        counter = 1
        ct = b''
        for i in range(0, len(pt), self.block_size):
            ct += self.xor(self._encrypt_block(int.to_bytes(counter, length=16)), pt[i:i + self.block_size])
            counter += 1
        return ct

for i in range(3*37):
    key = long_to_bytes(random.randint(0, 2**64))
    cipher = Feistel(key, rounds=7, block_size=16)
    
    pt = bytes.fromhex(input("Plaintext (hex) "))
    if len(pt) > 1000:
        print("Too long")
        exit()
    pt = cipher._pad(pt, cipher.block_size)

    ct = cipher.encrypt(pt)
    c = random.randint(0, 1)
    if c == 0:
        print(random.randbytes(len(ct)).hex())
    else:
        print(ct.hex())
    
    player = int(input("Guess what? "))
    if player != c:
        print(f"May you be lucky next time, {player} != {c}")
        exit()

print("Congrats, here is flag DEAD{redact}")
