from CTF_Library import *
from vinad import vinad

with open("output.txt") as file:
	R = ast.literal_eval(file.readline().split(" = ")[1])
	n = ast.literal_eval(file.readline().split(" = ")[1])
	c = ast.literal_eval(file.readline().split(" = ")[1])

while True:
	p = vinad(random.getrandbits(512), R)
	if n % p == 0:
		q = n // p
		break

while True:
	e = vinad(random.getrandbits(512), R)
	if gcd(e, (p - 1) * (q - 1)) == 1:
		flag = long_to_bytes((RSA_decrypt(p, q, e, c)[0] - sum(R)) % n)
		print(flag)
		break
