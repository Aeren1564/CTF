import os
import random
from math import log

from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot

from secret import flag

TARGET_LEN = 666
left_pad = random.randint(TARGET_LEN // 3, TARGET_LEN // 2)
right_pad = TARGET_LEN - left_pad - len(flag)
flag = os.urandom(left_pad) + flag + os.urandom(right_pad)


def sqrsqr(x: int, prec: int) -> tuple[int, int]:
    return int(iroot(x * 10 ** (prec * 4), 4)[0]) % 10**prec


class Server:
    # K: random integer in [0, 2^256)
    def __init__(self, bl: int, skip: int = 1000):
        self.bl = bl
        self.K = random.randrange(0, 2**self.bl)
        self.cipher = None
        self.key = None
        random.seed(self.K)

    # key = "keylen" frac part of K^{1/4} shuffled randomly, encoded in bytes
    def init_cipher(self, keylen: int):
        alpha = sqrsqr(self.K, prec=keylen)
        alpha_list = list(str(alpha).zfill(keylen))
        random.shuffle(alpha_list)
        self.key = long_to_bytes(int("".join(alpha_list)))

    def encrypt(self, m: bytes) -> bytes:
        keylen = round(log(10 ** len(m)) / log(10))
        self.init_cipher(keylen)
        sc = (len(m) + len(self.key) - 1) // len(self.key)
        return bytes([x ^ y for x, y in zip(m, self.key * sc)])


S = Server(bl=256)

print("Encrypted flag: ", S.encrypt(flag).hex())
while True:
    try:
        msg = bytes.fromhex(input("m: "))
        if len(msg) > 285:
            print("Message to big to encrypt, sorry")
        else:
            print("Encrypted msg: ", S.encrypt(msg).hex())
    except Exception as e:
        print(e)
        exit()
