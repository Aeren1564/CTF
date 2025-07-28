#!/usr/bin/env sage

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from random import randint
from secret import a, b, p, q, flag

Fp = GF(p)
Fq = GF(q)
E = EllipticCurve(Fp, [a, b])

class LCG:
    def __init__(self, seed, a, b):
        self.a, self.b = Fq(a), Fq(b)
        self.state = Fq(seed)

    def next_state(self):
        nxt = self.state * self.a + self.b
        self.state = nxt
        return int(nxt)

seed = randint(1, q)
lcg = LCG(seed, a, b)

collect, points = [], []

itr = 0
while len(collect) != 50:
    itr += 1
    y = lcg.next_state()
    P.<x> = PolynomialRing(Fp)
    try:
        x_ = (x^3+a*x+b-y^2).roots()[0][0]
        assert (x_, y) in E
        collect.append((itr, x_, Fp(y^2)))
        points.append((x_, Fp(y)))
    except:
        pass

qsz = q.bit_length()
qhi = q >> (qsz//2)
qlo = q & ((1 << (qsz//2)) - 1)

assert qhi.bit_length() == qsz//2
assert qlo.bit_length() == qsz//2

G = E.gens()[0]
hints = [
    sum([i[1]*G for i in points]).xy(),
    ((qhi^2 + (qlo^3)*69) * G).xy(),
    (((qhi^3)*420 + qlo^2) * G).xy()
]

for _ in range(10^18):
    lcg.next_state()

key = sha256(str(lcg.next_state()).encode()).digest()
ct = AES.new(key, AES.MODE_ECB).encrypt(pad(flag.encode(), 16)).hex()

with open('output.txt', 'w') as f:
    f.write(f'{collect=}\n')
    f.write(f'{hints=}\n')
    f.write(f'{ct=}')
