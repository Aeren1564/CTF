#!/usr/local/bin/python
from Crypto.Util.number import getPrime as gP
from random import choice, randint
p, q = gP(512), gP(512)
while p % 4 != 3:
    p = gP(512)

while q % 4 != 3:
    q = gP(512)

n = p * q
e = 0x10001

f = lambda x: ((choice([-1,1]) * pow(x, (p + 1) // 4, p)) * pow(q, -1, p) * q + (choice([-1,1]) * pow(x, (q + 1) // 4, q)) % q * pow(p, -1, q) * p) % n

while True:
    try:
        l = int(input(">>> ")) % n
        print(f(l))
    except:
        break

m = randint(0, n - 1)
print(f"{m = }")
s = int(input(">>> ")) % n
if pow(s,e,n) == m:
    print(open("flag.txt", "r").read())
else:
    print("Wrong signature!")
    exit(1)