from CTF_Library import *
from collections import defaultdict

point = []
with open("output.txt", "r") as out:
	enc_flag = bytes.fromhex(out.readline().split("'")[1])
	order = int(out.readline().split(" = ")[1])
	for _ in range(32 * 8):
		x, y = out.readline().strip().split(", ")
		x, y = int(x[1:]), int(y[:-1])
		point.append((x, y))
def recover_param():
	dif = []
	for i in range(len(point) - 1):
		x0, y0 = point[i]
		x1, y1 = point[i + 1]
		y0 = y0**2 - x0**3
		y1 = y1**2 - x1**3
		dif.append((x1 - x0, y1 - y0))
	mod = 0
	for i in range(len(point) - 2):
		x0, y0 = dif[i]
		x1, y1 = dif[i + 1]
		mod = gcd(mod, y1 * x0 - y0 * x1)
	a = dif[0][1] * pow(dif[0][0], -1, mod) % mod
	for x, y in dif:
		assert (a * x - y) % mod == 0
	b = (point[0][1] ** 2 - point[0][0]**3 - a * point[0][0]) % mod
	for x, y in point:
		assert (y**2 - x**3 - a * x - b) % mod == 0
	return mod, a, b
mod, a, b = recover_param()
assert not is_prime(mod)

singular_factors = [
	3562548874780288796769030192977
]

non_singular_factors = [
	(3692983360407686094702508373879, 1),
	(2717597692908121319788497985451, 388450213394528490535805887),
	(324094280281900209908870811008292068290746348301400744740589987, 1405747484361299393418580978953630281779614293727193),
]

list_key = [1] * (32 * 8)

def list_bitand(a, b):
	assert len(a) == 32 * 8 and len(b) == 32 * 8
	c = [0] * (32 * 8)
	for i in range(32 * 8):
		c[i] = a[i] & b[i]
	return c

print(f"[Processing singular curves]")
for p in singular_factors:
	print(f"{p = }")
	assert mod % p == 0 and is_prime(p)
	EC = custom_elliptic_curve(p, [a, b])
	s = 1688818121111580066310934554129
	cur = [1] * (32 * 8)
	for j in range(1, 32 * 8):
		if s * EC(*point[j - 1]) != EC(*point[j]):
			cur[j] = 0
	assert sum(cur) >= 32 * 3
	list_key = list_bitand(list_key, cur)
print("[End]\n")

print(f"[Processing non-singular curves]")
for p, large in non_singular_factors:
	print(f"{p = }, {large = }")
	print(f"{factor(p + 1) = }")
	assert mod % p == 0
	assert is_prime(p)
	assert large == 1 or is_prime(large)
	EC = EllipticCurve(GF(p), [a, b])
	assert EC.order() == p + 1 and (p + 1) % large == 0
	if large == 1:
		while True:
			i = random.randrange(1, 32 * 8)
			print(f"Trying {i = }")
			if list_key[i] == 0:
				continue
			s = MOV_attack(EC, EC(*point[i - 1]), EC(*point[i]))
			print(f"{s = }")
			cur = [1] * (32 * 8)
			for j in range(1, 32 * 8):
				if s * EC(*point[j - 1]) != EC(*point[j]):
					cur[j] = 0
			if sum(cur) >= 32 * 3:
				list_key = list_bitand(list_key, cur)
				break
	else:
		while True:
			i = random.randrange(1, 32 * 8)
			print(f"Trying {i = }")
			if list_key[i] == 0:
				continue
			s = (large * EC(*point[i])).log(large * EC(*point[i - 1]))
			print(f"{s = }")
			cur = [1] * (32 * 8)
			for j in range(1, 32 * 8):
				if s * large * EC(*point[j - 1]) != large * EC(*point[j]):
					cur[j] = 0
			if sum(cur) >= 32 * 3:
				list_key = list_bitand(list_key, cur)
				break
print("[End]\n")


print(f"{list_key = }")
def check_ans(list_key):
	key = 0
	for i in range(32 * 8):
		if list_key[i] == 1:
			key |= 1 << i
	flag = AES.new(key.to_bytes(32), AES.MODE_CTR, nonce = bytes(12)).decrypt(enc_flag)
	if ord('{') in flag and flag[-1] == ord('}'):
		print(flag)
		exit(0)
	else:
		print("Fail :(")
for last in range(2):
	list_key[0] = last
	check_ans(list_key)
