from CTF_Library import *

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
F = GF(p)
EC = EllipticCurve(F, [a, b])
FX = F["K1, K2"]
K1, K2 = FX.gens()
polys = []
with open("output.txt", "r") as out:
	for _ in range(10):
		coefs = []
		for _ in range(2):
			coef = []
			s = out.readline().strip()
			coef.append(int(s.split(" = ")[1].split(" * ")[0]))
			coef.append(int(s.split(" + ")[1]))
			coefs.append(coef)
		print(f"{coefs = }")
		ca, cb = map(F, coefs[0])
		cc, cd = map(F, coefs[1])
		Xp = ca * K1 + cb
		Xq = cc * K2 + cd
		polys.append((2 * Xp + Xq) * 4 * (Xp**3 + a * Xp + b) - (3 * Xp**2 + a)**2)
		print(f"{polys[-1] = }")
		print()
I = ideal(polys)
B = I.groebner_basis()
assert len(B) == 2 and all(f.degree() == 1 for f in B)
key1, key2 = int(-list(B[0])[1][0]), int(-list(B[1])[1][0])
key = int(key1) ^ int(key2)
print(f"Flag is DH{{{key:064x}}}")
