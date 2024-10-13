from CTF_Library import *

# BLS12-381 curve
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))

G1, G2 = E.gens()
o1, o2 = G1.order(), G2.order()
assert o1 == o2
p = 3 * 859267 * 52437899 * 52435875175126190479447740508185965837690552500527637822603658699938581184513

G1 *= p
G2 *= p
phi1, phi2 = E.isogeny(G2), E.isogeny(G1)

with open("chall.txt") as f:
	points = list(map(lambda x: E(x) * p, eval(f.read())))

def compute(args):
	i, x = args
	return i, phi1(x).log(phi1(G1)), phi2(x).log(phi2(G2))

c1, c2 = [None] * len(points), [None] * len(points)
with Pool(os.cpu_count()) as pool:
	for i, x1, x2 in pool.imap_unordered(compute, enumerate(points)):
		c1[i] = x1
		c2[i] = x2

for x in range(2):
	flag, last = x, x
	for i in range(1, len(c1)):
		if c1[i] == c1[i - 1] or c2[i] == c2[i - 1]:
			last ^= 1
		flag = flag << 1 | last
	flag = long_to_bytes(flag)
	if b"Alpaca{" in flag:
		print(flag)
	c1[0], c2[0] = c2[0], c1[0]