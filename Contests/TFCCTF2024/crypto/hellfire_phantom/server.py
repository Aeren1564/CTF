from sage.all import *
import random
from Crypto.Util.number import getPrime, isPrime, long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import sha256

FLAG = b'REDACTED'
secret = REDACTED
b_curve = REDACTED




p = 1154543773027194978300531105544404721440832315984713424625039
g = 2
shared = pow(g,secret,p)

print(f"p = {p}")
print(f"g = {g}")
print(f"shared = {shared}")


secret2 = bytes_to_long(FLAG)


p_curve = 4470115461512684340891257138125051110076800700282905015819080092370422104067183317016903680000000000000001
a_curve = 35220

Z = GF(p_curve)
E = EllipticCurve(Z, [a_curve,b_curve])
G = E.lift_x(Z(secret))
P = G * secret2

print(f'p_curve = {p_curve}')
print(f'a_curve = {a_curve}')
print(f'P = {P}')