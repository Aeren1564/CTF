import os
from Crypto.Cipher import AES
from hashlib import sha256

FLAG = os.environ.get("FLAG", "fakeflag")

N = 509
q = 2048
p = 3
d = 253

Zx.<x> = ZZ[]

def invertmodprime(f, p):
    T = Zx.change_ring(Integers(p)).quotient(x ^ N - 1)
    return Zx(lift(1 / T(f)))

def invertmodpowerof2(f, q):
    assert q.is_power_of(2)
    h = invertmodprime(f, 2)
    while True:
        r = balancedmod(convolution(h, f), q)
        if r == 1:
            return h
        h = balancedmod(convolution(h, 2 - r), q)

def balancedmod(f, q):
    g = list(((f[i] + q // 2) % q) - q // 2 for i in range(N))
    return Zx(g)

def convolution(f, g):
    return (f * g) % (x ^ N - 1)

def generate_polynomial(d):
    coeffs = [1] * d + [0] * (N - d)
    shuffle(coeffs)
    return Zx(coeffs)

def generate_keys():
    while True:
        try:
            f = generate_polynomial(d)
            g = generate_polynomial(d)
            f_p = invertmodprime(f, p)
            f_q = invertmodpowerof2(f, q)
            break
        except:
            pass
    public_key = balancedmod(p * convolution(f_q, g), q)
    secret_key = f, f_p
    return public_key, secret_key

def generate_message():
    result = list(randrange(2) for j in range(N))
    return Zx(result)

def encrypt(message, public_key):
    r = Zx(list(randrange(2) for j in range(N)))
    return balancedmod(convolution(public_key, r) + message, q)


msg = generate_message()

public_keys = []
ciphertexts = []
for _ in range(777):
    public_key, secret_key = generate_keys()
    ct = encrypt(msg, public_key)
    public_keys.append(public_key)
    ciphertexts.append(ct)

print("public keys:", public_keys)
print("ciphertexts:", ciphertexts)

key = sha256(str(msg).encode()).digest()[:16]
cipher = AES.new(key=key, mode=AES.MODE_CTR)
enc_flag = cipher.encrypt(FLAG.encode())
print("encrypted flag:", (cipher.nonce + enc_flag).hex())
