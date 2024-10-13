import os
import random
from math import prod
from Crypto.Util.number import isPrime, bytes_to_long

r = random.Random(0)
def deterministicGetPrime():
  while True:
    if isPrime(p := r.getrandbits(64)):
      return p

# This is not likely to fail
assert deterministicGetPrime() == 2710959347947821323, "Your Python's random module is not compatible with this challenge."

def getPrime(bit):
  factors = [deterministicGetPrime() for _ in range(bit // 64)]
  cnt = 0
  while True:
    p = 2 * prod(factors) + 1
    if isPrime(p):
      print(f"{cnt = }")
      return p
    cnt += 1
    factors.remove(random.choice(factors))
    factors.append(deterministicGetPrime())

flag = os.environ.get("FLAG", "fakeflag").encode()
m = bytes_to_long(flag)

p, q = getPrime(1024), getPrime(1024)
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"{n=}")
print(f"{e=}")
print(f"{c=}")
