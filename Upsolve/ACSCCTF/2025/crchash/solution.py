from CTF_Library import *
from chall import crchash, MASK

R = GF(2)['x']
x = R.gen()

def to_poly(i):
	poly = R(0)
	for bit in range(i.bit_length()):
		if i >> bit & 1:
			poly += x**bit
	return poly

def to_int(poly):
	i = 0
	for bit, c in enumerate(poly.list()):
		if c:
			i |= 1 << bit
	return i

mod = R(0)
while mod == 0 or mod.degree() > 64:
	with remote("host1.dreamhack.games", 14295) as io:
		m = int(io.readlineS().strip())
		h = int(io.readlineS().strip())
		mod = gcd(mod, to_poly(m << 64) - to_poly(h))
assert mod.degree() == 64
assert mod % x**4 == 0
mod //= x**4

with remote("host1.dreamhack.games", 14295) as io:
	m = to_poly(int(io.readlineS().strip())) % mod
	h = int(io.readlineS().strip())
	for mask in range(16):
		i = to_int(m + to_poly(mask) * mod)
		assert 0 <= i < 2**64
		assert crchash((i & MASK).to_bytes(8, byteorder = "big")) == h
		io.sendline(str(i).encode())
	print(io.readallS(timeout = 1))

"""
a * x**60 = h/x**4 mod poly/x**4
"""
