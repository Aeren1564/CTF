from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, long_to_bytes
import random
import math

# generate parameters
bit_length = 256
M = getPrime(bit_length)

# ensure that A and C are within M
A = random.randint(1, M)
C = random.randint(1, M)


def my_lcg():
    # my version of lcg, but I think xor is more efficient than multiply
    init_state = random.randint(1, M)
    while True:
        yield int(init_state)
        init_state = (init_state ^ A + C) % M


my_random = my_lcg()

# give it some times to warm up
for _ in range(10):
    next(my_random)

# encrypt my message!
flag = open("./flag.txt", "rb").read()
raw_keys = [long_to_bytes(next(my_random)) for _ in range(2)]
key = SHA256.new(b"".join(raw_keys)).digest()
raw_nonce = [long_to_bytes(next(my_random)) for _ in range(2)]
nonce = SHA256.new(b"".join(raw_nonce)).digest()
cipher = AES.new(key=key, mode=AES.MODE_CTR, nonce=nonce[:12]).encrypt(flag)
print("Here is your encrypted message:")
print(cipher.hex())

# oops heres some hint for you
print("Here is your hint:")
for _ in range(50):
    print(next(my_random))
