import os
import random
from Crypto.Util.number import bytes_to_long

flag = os.environ.get("FLAG", "fakeflag").encode()
bit_length = len(flag) * 8

# BLS12-381 curve
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))

G1, G2 = E.gens()
o1, o2 = G1.order(), G2.order()

xs = [random.randrange(0, o1) for _ in range(bit_length + 1)]
m = bytes_to_long(flag)

cs = []
for c, (x1, x2) in zip(bin(m)[2:].zfill(bit_length), zip(xs[:-1], xs[1:])):
  if c == "1":
    x1, x2 = x2, x1
  cs.append(x1 * G1 + x2 * G2)

print([P.xy() for P in cs])
