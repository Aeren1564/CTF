from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from fastecdsa.curve import secp256k1
from hashlib import sha256
from secrets import randbelow


G = secp256k1.G
q = secp256k1.q
mask = 0
i = 0

def sign(d, z, k):
    global i
    global mask
    r = (k * G).x
    if z + (r * d) % q < q:
        mask |= 1 << i
    print(i, mask)
    i += 1
    s = (z + r * d) * pow(k, -1, q) % q
    return r, s


def verify(P, z, r, s):
    u1 = z * pow(s, -1, q) % q
    u2 = r * pow(s, -1, q) % q
    x = (u1 * G + u2 * P).x
    return x == r


def lcg(a, b, p, x):
    while True:
        x = (a * x + b) % p
        yield x


msgs = [
    b"https://www.youtube.com/watch?v=kv4UD4ICd_0",
    b"https://www.youtube.com/watch?v=IijOKxLclxE",
    b"https://www.youtube.com/watch?v=GH6akWYAtGc",
    b"https://www.youtube.com/watch?v=Y3JhUFAa9bk",
    b"https://www.youtube.com/watch?v=FGID8CJ1fUY",
    b"https://www.youtube.com/watch?v=_BfmEjHVYwM",
    b"https://www.youtube.com/watch?v=zH7wBliAhT0",
    b"https://www.youtube.com/watch?v=NROQyBPX9Uo",
    b"https://www.youtube.com/watch?v=ylH6VpJAoME",
    b"https://www.youtube.com/watch?v=hI34Bhf5SaY",
    b"https://www.youtube.com/watch?v=bef23j792eE",
    b"https://www.youtube.com/watch?v=ybvXNOWX-dI",
    b"https://www.youtube.com/watch?v=dt3p2HtLzDA",
    b"https://www.youtube.com/watch?v=1Z4O8bKoLlU",
    b"https://www.youtube.com/watch?v=S53XDR4eGy4",
    b"https://www.youtube.com/watch?v=ZK64DWBQNXw",
    b"https://www.youtube.com/watch?v=tLL8cqRmaNE",
]

if __name__ == "__main__":
    #d = randbelow(q)
    d = 15536867330988408474992152340377233221418858456921712303879310164997996596744

    P = d * G

    # G: EC base point     -> fixed
    # q = ord(G)           -> fixed 256 bit
    # d < q                -> Random 256 bit

    # p = getPrime(0x137) # 311 bits
    # a, b, x = [randbelow(p) for _ in range(3)]
    p, a, b, x = 2610224986074366012980387755376767838220600120932138474778551204720720951873853073317956501089, 495886586642483401082439313825564901654231642609800718472682620476505252745280434979929147069, 332135700899030366000954701357147445802595885521391159012012109753896326113491341823036282936, 2594352554531084042864962246759897686030709029598080329577528243705785375036795767314858504410
    rng = lcg(a, b, p, x)

    sigs = []
    for m, k in zip(msgs, rng):
        z = int.from_bytes(sha256(m).digest(), "big") % q

        # k                                      -> random dep on LCG
        # z < q                                  -> fixed

        r, s = sign(d, z, k)

        # r(ki) = (ki * G).x                     -> random dep on LCG
        # s(ki, d) = (z + r(ki) * d) / ki mod q  -> random dep on LCG

        assert verify(d * G, z, r, s)

        # x = ((z / s(ki, d) mod q) * G + (r(ki) / s(ki, d) mod q) * d * G).x
        # return x == r(k)

        sigs.append((r, s))
    print(f"{sigs = }")

    # OBJECTIVE: find d

    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    key = sha256(str(d).encode()).digest()
    nonce = b'\x01AN\xa6\xd0\xe0\xebI'
    cipher = AES.new(key, AES.MODE_CTR, nonce = b'\x01AN\xa6\xd0\xe0\xebI')
    ct = cipher.encrypt(flag)
    nonce = cipher.nonce
    print(f"{ct = }")
    print(f"{nonce = }")
    print(mask)