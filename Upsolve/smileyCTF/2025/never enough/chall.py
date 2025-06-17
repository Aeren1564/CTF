from random import getrandbits
from Crypto.Cipher import AES
from hashlib import sha256
danger = 624*32 # i hear you need this much.
given = []
key = ""
for _ in range(danger//20 - 16): # should be fine if im only giving u this much :3
    x = getrandbits(32)
    # we share <3
    key += str(x % 2**12)
    given.append(x >> 12)

key = key[:100]
key = sha256(key.encode()).digest()
flag = open("flag.txt", "rb").read().strip()
cipher = AES.new(key, AES.MODE_ECB)
print(given)
print(cipher.encrypt(flag + b"\x00" * (16 - len(flag) % 16)).hex())