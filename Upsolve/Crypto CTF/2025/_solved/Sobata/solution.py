from CTF_Library import *

while True:
	#with process(["sage", "sobata.sage"]) as io:
	with remote("91.107.161.140", 11177) as io:
		def read_point():
			return ast.literal_eval(io.readlineS().strip().split(": ")[1])
		def walk(x, y):
			io.readlines(5)
			io.sendline(b"w")
			io.readline()
			io.sendline((str(x) + "," + str(y)).encode())
			return read_point()
		def jump(x, y, n):
			io.readlines(5)
			io.sendline(b"j")
			io.readline()
			io.sendline((str(x) + "," + str(y)).encode())
			io.readline()
			io.sendline(str(n).encode())
			return read_point()
		io.readlines(9)
		io.sendline(b"e")
		ex, ey = read_point()
		data = [(ex, ey)]
		for _ in range(10):
			data.append(walk(*data[-1]))
		p = 0
		x, y = ex, ey
		while not is_prime(p):
			nx, ny = walk(x, y)
			p = gcd(p, (x**3 - y**2) - (nx**3 - ny**2))
			x, y = nx, ny
		d = (ey**2 - ex**3) % p
		print(f"{p = }")
		print(f"{d = }")
		F = GF(p)
		E = EllipticCurve(F, [0, d])
		x, y = ex, ey
		try:
			for _ in range(6):
				x, y = jump(x, y, 0)
			if (x, y) != (ex, ey):
				print(f"Something went wrong")
				exit(0)
			for _ in range(5):
				x, y = jump(x, y, 0)
			x, y = jump(x, y, -1)
			for _ in range(5):
				x, y = jump(x, y, 0)
			print(long_to_bytes(x))
			break
		except:
			print(f"c is not coprime with order :(")

"""
p: random prime 1 mod 6
E: elliptic curve Y^2=X^3+d modulo p, where d is random
a: primitive cubic root of unity
b: p-1
c: random

walk: (x, y) -> c * (a * x, b * y)
jump: (x, y) -> c^n * (a * x, b * y)

we're given c * (a * fx, b * fy)

"""