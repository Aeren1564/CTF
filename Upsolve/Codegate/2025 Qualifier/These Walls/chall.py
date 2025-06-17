from secret import P, s, o, wrong, flag
from Crypto.Cipher import AES
import random, os, math

assert P * o == P.curve()(0)
assert all(math.gcd(o, w) == 1 for w in wrong + [s])
assert all(P * s != P * w for w in wrong)

key = os.urandom(32)
enc_flag = AES.new(key, AES.MODE_CTR, nonce=bytes(12)).encrypt(flag.encode())

print(f"{enc_flag.hex() = }\n{o = }")

key = int.from_bytes(key)
for i in range(32 * 8):
	P *= [random.choice(wrong), s][(key >> i) & 1]
	print(P.xy())