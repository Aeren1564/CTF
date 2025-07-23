from CTF_Library import *

nbit = 196
R = ZZ['g']
g = R.gen()
f = g**2 + 13 * g + 37

while True:
	with remote("91.107.252.0", 11173) as io:
	# with process(["sage", "sobata_II.sage"]) as io:
		io.readlines(4)
		def read_point():
			return eval(io.readlineS().strip().split(": ")[1])
		def get_enc_flag():
			io.readlines(5)
			io.sendline(b"e")
			return read_point()
		def walk(x, y):
			io.readlines(5)
			io.sendline(b"w")
			io.readline()
			io.sendline(",".join([str(x), str(y)]).encode())
			return read_point()
		def jump(x, y, n):
			io.readlines(5)
			io.sendline(b"j")
			io.readline()
			io.sendline(",".join([str(x), str(y)]).encode())
			io.readline()
			io.sendline(str(n).encode())
			return read_point()
		ex, ey = get_enc_flag()
		print(f"{ex = }")
		print(f"{ey = }")
		p = 0
		x, y = deepcopy(ex), deepcopy(ey)
		while not is_prime(p):
			nx, ny = walk(x, y)
			dif = ((x**3 - y**2) - (nx**3 - ny**2)) % f
			p = gcd(list(dif)[0], p)
			p = gcd(list(dif)[1], p)
			x, y = deepcopy(nx), deepcopy(ny)
		d = list((ey**2 - ex**3) % f)[0] % p
		print(f"{p = }")
		print(f"{d = }")
		x, y = deepcopy(ex), deepcopy(ey)
		for _ in range(6):
			x, y = jump(x, y, 0)
		assert (x, y) == (ex, ey)
		for _ in range(5):
			x, y = jump(x, y, 0)
		try:
			x, y = jump(x, y, -1)
		except:
			print(f"c is not coprime with order :(")
			continue
		for _ in range(5):
			x, y = jump(x, y, 0)
		print(f"Final {x = }")
		print(long_to_bytes(int(list(x)[0])))
		break

"""
F: GF(p^2) where modulus is x^2 + 13x + 37
g: F.gen()
E: Elliptic curve Y^2 = X^3 + d over F where d is random int in [1, p]
a: primitive cubic root
b: -1
c: random int in [1, p]

walk(x, y) -> c * (a * x, b * y)
jump(x, y) -> c^n * (a * x, b * y)
"""