from CTF_Library import *

def rot(n, r):
	return (n >> r) | ((n << (256 - r) & (2**256 - 1)))

round_constants1 = [3, 141, 59, 26, 53,  58]
round_constants2 = [2, 7,   18, 28, 182, 8 ]

M = 2**256

def encrypt(key, block):
	for i in range(6):
		block = (block + key) & (M-1)
		block = block ^ rot(block, round_constants1[i]) ^ rot(block, round_constants2[i])
	return block

def revert_xor(x: int, round_index: int = 5):
	assert 0 <= round_index < 6
	bv = make_bit_vectors([256])[0]
	bv ^= bv.rotr(round_constants1[round_index]) ^ bv.rotr(round_constants2[round_index])
	solver = linear_equation_solver_GF2(256)
	for bit in range(256):
		assert solver.add_equation_if_consistent(bv[bit], x >> bit & 1)
	res = solver.solve()[0]
	assert (res ^ rot(res, round_constants1[round_index]) ^ rot(res, round_constants2[round_index])) == x
	return res

def encrypt_without_last(key, block):
	return revert_xor(encrypt(key, block))

key = bytes_to_long(os.urandom(32))
block = bytes_to_long(os.urandom(32))

key = 46101409641337289479449736029171619543411422242970730223922768384540678463041

dif = [[] for _ in range(256)]
for it in range(10):
	print(f"{it = }")
	base = bytes_to_long(os.urandom(32))
	for target in range(256):
		q0 = int(base)
		for bit in range(target - 5, target + 6):
			q0 &= ~(1 << (bit % 256))
		q1 = q0 | 1 << target
		dif[target] += [(encrypt_without_last(key, q0) ^ encrypt_without_last(key, q1)).bit_count()]

for bit in range(256):
	print(bit, key >> bit & 1)
	print(sorted(dif[bit]))
	print()
