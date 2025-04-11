from CTF_Library import *

with remote("35.187.238.100", 5001) as io:
	io.readlinesS(3)
	work = io.readlineS().strip()
	io.readuntilS(b"Suffix: ")

	prefix = work.split("\"")[1]

	for x in range(10**9):
		if hashlib.sha256((prefix + str(x)).encode()).digest().hex().startswith("000000"):
			print(f"PoW solved, {x = }")
			io.sendline(str(x).encode())
			break

	print(f"Solver start")
	p = int(io.readlineS().strip().split("= ")[1])
	F = GF(p)
	print(f"{p = }")
	io.readuntil(b"Gib me the queries: ")
	q = [x for x in range(1, 33) for y in range(1 if x >= 31 else (x - 1) // 2 + 1)]
	assert len(q) <= 256
	io.sendline(" ".join(map(str, q)).encode())
	cnt = {}
	for y in literal_eval(io.readlineS().strip().split("= ")[1]):
		if y not in cnt:
			cnt[y] = 0
		cnt[y] += 1
	appear = [[] for _ in range(16)]
	for x, y in cnt.items():
		appear[y].append(x)
	assert len(appear[1]) == 4
	assert all(len(appear[k]) == 2 for k in range(2, 16))

	xs, ys = [0] * 32, [x for c in appear for x in c]

	def solve(perm):
		perm = list(perm)
		for mask in range(2**14):
			xs[: 4] = perm[:]
			for c in range(2, 16):
				if mask >> c - 2 & 1:
					xs[2 * c], xs[2 * c + 1] = 2 * c - 1, 2 * c
				else:
					xs[2 * c], xs[2 * c + 1] = 2 * c, 2 * c - 1
			poly = F['X'].lagrange_polynomial(zip(map(F, xs), map(F, ys)))
			for c in map(int, list(poly)):
				flag = long_to_bytes(c)
				if b"ISITDTU{" in flag:
					return flag

	for perm in itertools.permutations([1, 2, 31, 32]):
		flag = solve(perm)
		print(f"{flag = }")
		if flag is not None:
			break
