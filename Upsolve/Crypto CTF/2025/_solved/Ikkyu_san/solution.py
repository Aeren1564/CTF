from CTF_Library import *

while True:
	with remote("91.107.132.34", 37773) as io:
		io.readlines(5)
		def get_random_point():
			io.readlines(5)
			io.sendline(b"r")
			x, y, z = map(int, io.readlineS().strip().split(" = ")[1][1:-1].split(" : "))
			return x, y
		def get_enc():
			io.readlines(5)
			io.sendline(b"e")
			return int(io.readlineS().strip().split(" = ")[1])
		def query(x, y):
			io.readlines(5)
			io.sendline(b"g")
			io.readline()
			io.sendline((str(x) + "," + str(y)).encode())
			x, y, z = map(int, io.readlineS().strip().split(" = ")[1][1:-1].split(" : "))
			return x, y
		enc = get_enc()
		points = []
		p = 0
		while not is_prime(p):
			data = []
			for _ in range(3):
				x, y = get_random_point()
				points.append([x, y])
				data.append([y**2 - x**3, x])
			data = [
				[data[i][0] - data[i + 1][0], data[i][1] - data[i + 1][1]]
				for i in range(2)
			]
			p = gcd(p, data[0][0] * data[1][1] - data[0][1] * data[1][0])
		F = GF(p)
		data = []
		for x, y in points[:2]:
			data.append([y**2 - x**3, x])
		a = (data[1][0] - data[0][0]) * pow(data[1][1] - data[0][1], -1, p) % p
		b = (points[0][1]**2 - points[0][0]**3 - a * points[0][0]) % p
		for x, y in points:
			assert (x**3 + a * x + b - y**2) % p == 0
		EC = EllipticCurve(F, [a, b])
		if EC.order() % 2 == 0:
			print(f"I hate this curve order")
			continue
		x, y = get_random_point()
		P = EC(*query(x, y)) + EC(*query(x, p - y))
		while True:
			z, w = get_random_point()
			Q = EC(*query(z, w)) + EC(*query(z, p - w))
			if gcd(x - z, EC.order()) == 1:
				break
		G = pow(2 * (x - z), -1, EC.order()) * (P - Q)
		while True:
			x, y = get_random_point()
			if gcd(y, EC.order()) == 1:
				P = EC(*query(x, y))
				break
		H = pow(y, -1, EC.order()) * (P - x * G - int(G.x()) * EC(x, y))
		print(long_to_bytes(int(enc / G.x() / H.y())))
		break

"""
p: random 256 bit prime
E: Y^2=X^3+aX+b where a, b are random
G, H: random points on E
b + a + 1 and b - a - 1 must not be square mod p

query point P
-> get Px * G + Py * H + Gx * P

ask for random point

ask for flag * Gx * Hy

y0^2 - x0^3 = a*x0 + b
y1^2 - x1^3 = a*x1 + b
y2^2 - x2^3 = a*x2 + b


x * G + y * H + Gx * (x, y)
x * G + (p - y) * H + Gx * (x, p - y)

P = 2 * x * G + p * H

"""