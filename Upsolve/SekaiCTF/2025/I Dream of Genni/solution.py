from CTF_Library import *

def dream_multiply(x, y):
	x, y = str(x), str(y)
	assert len(x) == len(y) + 1
	digits = x[0]
	for a, b in zip(x[1:], y):
		digits += str(int(a) * int(b))
	return int(digits)

res = [(0, 0, "")]

for pos in range(7):
	res_next = []
	p10 = 10**pos
	for x, y, comb in res:
		for dx, dy in itertools.product(range(1, 10), repeat = 2):
			nx = dx * p10 + x
			ny = dy * p10 + y
			ncomb = str(dx * dy) + comb
			if dx * dy < 10:
				if len(comb) >= 2 * pos and (int(ncomb) - nx * ny) % (p10 * 10) == 0:
					res_next.append((nx, ny, ncomb))
			else:
				if (int(ncomb) - nx * ny) % (p10 * 10) == 0:
					res_next.append((nx, ny, ncomb))
	res = res_next
	print(f"{pos = }")
	print(f"{len(res) = }")
	print()

ct = bytes.fromhex("75bd1089b2248540e3406aa014dc2b5add4fb83ffdc54d09beb878bbb0d42717e9cc6114311767dd9f3b8b070b359a1ac2eb695cd31f435680ea885e85690f89")

def f(res):
	for x, y, comb in res:
		for _ in range(9):
			x += 10**7
			if dream_multiply(x, y) == x * y:
				print(f"{x = }, {y = }")
				try:
					flag = AES.new(hashlib.sha256(str((x, y)).encode()).digest(), AES.MODE_ECB).decrypt(ct).decode()
					print(flag)
				except Exception as e:
					print("FAIL :(")

with ProcessPoolExecutor(os.cpu_count()) as executor:
	jump = len(res) // os.cpu_count() + 1
	for flag in executor.map(f, (res[i : i + jump] for i in range(0, len(res), jump))):
		pass
