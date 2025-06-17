from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
from secrets import randbelow, choice
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from string import ascii_letters, digits
from flag import flag


key = "".join([choice(ascii_letters + digits) for i in range(150)]).encode()

blocklen = len(key)//5
polsize = 25
maxexp = 3

V, W, X, Y, Z = [bytes_to_long(b) for b in [key[blocklen*i:blocklen*i+blocklen] for i in range(5)]]

n = getPrime(4096)*getPrime(4096)*getPrime(4096)*getPrime(4096)
n = n^2

K = Zmod(n)
PP.<v, w, x, y, z> = PolynomialRing(K)

coeffs = [K.random_element() for i in range(polsize)]

pol = 0
for l in range(polsize):
    while True:
        i, j, k, s, t = [randbelow(maxexp) for _ in range(5)]
        if i == j == k == s == t == 0: continue
        pol = pol + coeffs[l] * v^i * w^j * x^k * y^s * z^t
        if len(pol.coefficients()) == l + 1:
            break

c = pol(V, W, X, Y, Z)
pol = pol - c
assert pol(V, W, X, Y, Z) == 0

key = sha256(key).digest()
cipher = AES.new(key, AES.MODE_ECB)
c = cipher.encrypt(pad(flag, 16)).hex()

with open("output.txt", "w") as f:
    f.write(f"{blocklen = }\n")
    f.write(f"{n = }\n")
    f.write(f"{pol = }\n")
    f.write(f"{c = }\n")



