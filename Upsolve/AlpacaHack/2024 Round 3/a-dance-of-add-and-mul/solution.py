from CTF_Library import *

# BLS12-381 curve
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))

G1, G2 = E.gens()
o1, o2 = G1.order(), G2.order()
assert o1 == o2
p = max(x for x, _ in factor(o1))

G1 *= p
G2 *= p
with open("chall.txt") as f:
	points = [p * E(x) for x in eval(f.read())]

for x in range(2):
	flag, last = x, x
	for i in range(len(points) - 1):
		try:
			(points[i + 1] - points[i]).log(G1)
			last ^= 1
		except:
			try:
				(points[i + 1] - points[i]).log(G2)
				last ^= 1
			except:
				pass
		flag = flag << 1 | last
	flag = long_to_bytes(flag)
	if b"Alpaca{" in flag:
		print(flag)
