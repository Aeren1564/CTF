#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

l, flag = 14, flag.lstrip(b'CCTF{').rstrip(b'}')
FLAG = [flag[l * i:l * (i + 1)] for i in range(len(flag) // l)]
M = [bytes_to_long(_) for _ in FLAG]
p = getPrime(313)

R.<u, v, w, x, y, z> = PolynomialRing(QQ)

COEFS = [getRandomRange(1, p - 1) for _ in range(21)]

f = COEFS[0] * u * v + COEFS[1] * u + COEFS[2] * v
g = COEFS[3] * u * x * y + COEFS[3] * x + COEFS[5] * y + COEFS[6] * v
h = COEFS[7] * u * w + COEFS[8] * w + COEFS[9] * u
i = COEFS[10] * v * y * z + COEFS[11] * y + COEFS[12] * z + COEFS[13] * w
j = COEFS[14] * v * w + COEFS[15] * v + COEFS[16] * w
k = COEFS[17] * w * z * x + COEFS[18] * z + COEFS[19] * x + COEFS[20] * u

f, g, h, i, j, k = R(f), R(g), R(h), R(i), R(j), R(k)
CNST = [_(M[0], M[1], M[2], M[3], M[4], M[5]) for _ in [f, g, h, i, j, k]]
f, g, h, i, j, k = [[f, g, h, i, j, k][_] + (p - CNST[_]) % p for _ in range(6)]

print(f'{p = }')
print(f'{f = }')
print(f'{g = }')
print(f'{h = }')
print(f'{i = }')
print(f'{j = }')
print(f'{k = }')