from CTF_Library import *

with open("output.txt", 'r') as out:
	a = list(map(float, out.read().strip().split('\n')))
n = len(a)
assert n % 24 == 0

def xorshift(bv):
	bv = [bv[1].copy(), bv[0].copy()]
	bv[1] ^= bv[1] << 23
	bv[1] ^= bv[1] >> 17
	bv[1] ^= bv[0]
	bv[1] ^= bv[0] >> 26
	return bv

secretbits = ""
for start in range(0, n, 24):
	bv = make_bit_vectors([64, 64])
	solver = linear_equation_solver_GF2(128)
	bvs = [bv]
	for i in range(63):
		bvs.append(xorshift(bvs[-1]))
	bvs = bvs[::-1]
	c = '0'
	for i in range(24):
		x = int(2**64 * a[start + i])
		for j in range(64 - 53, 64):
			if not solver.add_equation_if_consistent(bvs[i][0][j], x >> j & 1):
				c = '1'
				break
		if c == '1':
			break
	secretbits += c
assert len(secretbits) % 8 == 0
secret = ""
for start in range(0, len(secretbits), 8):
	x = 0
	for c in secretbits[start : start + 8]:
		x = 2 * x + ord(c) - ord('0')
	secret += chr(x)
print(secret)
