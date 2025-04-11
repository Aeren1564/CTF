# NIST P-256 Parameters
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

Zp = Zmod(p)
P256 = EllipticCurve(Zp, [a, b])

key1 = Zp.random_element()
key2 = Zp.random_element()

for _ in range(10):
    P = P256.random_point()
    Q = P + P

    b = Zp.random_element()
    a = (P.xy()[0] - b) / key1

    d = Zp.random_element()
    c = (Q.xy()[0] - d) / key2

    print(f"P.x = {a} * key1 + {b}")
    print(f"Q.x = {c} * key2 + {d}")

with open('flag', 'w') as f:
    key = int(key1) ^^ int(key2)
    f.write(f"Flag is DH{{{key:064x}}}")