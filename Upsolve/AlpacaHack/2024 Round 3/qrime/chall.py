import os
from Crypto.Util.number import bytes_to_long, getRandomNBitInteger, isPrime

def nextPrime(n):
    while not isPrime(n := n + 1):
        continue
    return n

def gen():
    while True:
        q = getRandomNBitInteger(256)
        r = getRandomNBitInteger(256)
        p = q * nextPrime(r) + nextPrime(q) * r
        if isPrime(p) and isPrime(q):
            return p, q, r

flag = os.environ.get("FLAG", "fakeflag").encode()
m = bytes_to_long(flag)

p, q, r = gen()
n = p * q

phi = (p - 1) * (q - 1)
e = 0x10001
d = pow(e, -1, phi)
c = pow(m, e, n)

print(f"{n=}")
print(f"{e=}")
print(f"{c=}")
print(f"{r=}")
