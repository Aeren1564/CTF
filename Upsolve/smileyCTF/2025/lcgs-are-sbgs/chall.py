import random
from Crypto.Util.number import *
import hashlib

flag = open("flag.txt", "rb").read().strip()

assert flag[:6] == b".;,;.{"
assert flag[-1:] == b"}"
flag = flag[6:-1]

class ComplexNumber():
    def __init__(self, r, i):
        self.num = [r, i]

    def __repr__(self):
        return f"{self.num[0]} + {self.num[1]}*I"

    def __getitem__(self, item):
        return self.num[item]

    def __add__(self, other):
        return ComplexNumber(self.num[0] + other[0], self.num[1] + other[1])

    def __sub__(self, other):
        return ComplexNumber(self.num[0] - other[0], self.num[1] - other[1])

    def __mul__(self, other):
        p1 = self.num[0]*other[0] - self.num[1]*other[1]
        p2 = self.num[1]*other[0] + self.num[0]*other[1]
        return ComplexNumber(p1, p2)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __mod__(self, other):
        return ComplexNumber(self.num[0] % other, self.num[1] % other)

bits = 96
p = None
while True:
    p = getPrime(bits)
    if p.bit_length() == bits and pow(-1,(p-1)//2,p) == p-1:
        break
a = ComplexNumber(random.randint(0, p), random.randint(0, p))
b = ComplexNumber(random.randint(0, p), random.randint(0, p))
seed = ComplexNumber(random.randint(0, p), random.randint(0, p))

def lcg():
    x = seed
    while True:
        x = (a*x + b) % p
        yield [x[0] >> (bits - 8), x[1] >> (bits - 8)]

LCG = lcg()

hint = b""
for h,_ in zip(LCG, range(bits)):
    hint += bytes([h[0], h[1]])

enc_key = b""
for key_byte, char in zip(LCG, range(8)):
    enc_key += bytes([key_byte[0], key_byte[1]])

enc_key = hashlib.sha256(enc_key).digest()
enc_flag = bytes([a ^ b for a, b in zip(flag, enc_key)])

print(f"{p = }")
print(f"{a = }")
print(f"hint = {hint.hex()}")
print(f"enc_flag = {enc_flag.hex()}")
