import os
import secrets
from Crypto.Util.number import getPrime, isPrime, bytes_to_long

FLAG = os.environ.get("FLAG", "fakeflag").encode()

p = getPrime(768)
q = getPrime(768)

ns = [p * q]
for _ in range(3):
    while True:
        delta = secrets.randbelow(2**192)
        new_p = p + delta
        new_q = q + delta
        if isPrime(new_p) and isPrime(new_q):
            ns.append(new_p * new_q)
            break

seps = [len(FLAG) // 4 * i for i in range(4)] + [len(FLAG)]
ms = [bytes_to_long(FLAG[start:end]) for start, end in zip(seps[:-1], seps[1:])]
e = 0x10001

assert len(ms) == len(ns) == 4

for i, (m, n) in enumerate(zip(ms, ns)):
    assert m < n
    c = pow(m, e, n)
    print(f"n{i}={n}")
    print(f"c{i}={c}")
