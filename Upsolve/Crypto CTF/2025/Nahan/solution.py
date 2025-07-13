from CTF_Library import *

for flag_len in range(31, 10**5):
	l = flag_len * 8
	with remote("91.107.252.0", 33737) as io:
		io.readlines(8)
		io.sendline(b"g")
		io.readline()
		x = 2**(l // 3 + 1) - 1
		io.sendline(",".join([str(x), str(x)]).encode())
		if io.readlineS().strip() != "┃ Your input does not meet the requirements!!!":
			break
l, step = flag_len << 3, flag_len << 2
print(f"{flag_len = }")
print(f"{l = }")
print(f"{step = }")
print()

def next_prime(n):
	while True:
		if isPrime(n): return n
		else: n += 1

# TODO: try solving bits in chunk of 20

with process(["python3", "nahan.py"]) as io:
	io.readlines(4)
	solver = inequality_solver_with_SVP([0] * l, [1] * l)
	for _ in range(step):
		io.readlines(4)
		io.sendline(b"g")
		io.readline()
		s, t = random.getrandbits(l // 2 - 1), random.getrandbits(l // 2 - 1)
		io.sendline(",".join([str(s), str(t)]).encode())
		x = int(io.readlineS().strip().split(" = ")[1])
		p = next_prime(s * t ^ 2**l)
		print(f"Step {_}")
		print(f"{p = }")
		print(f"{x = }")
		print(f"{x % p = }")
		assert x % p == 0
		x //= p
		x = bin(x).count('1') - 1
		coef = [1] * l
		value = x
		for i in range(l):
			if p >> i & 1:
				coef[i] = -1
				value -= 1
		solver.add_equality(coef, value)
		print(solver.solve())

	cur = 0
	# for pivot in range(l):
	# 	print(f"{pivot = }")
	# 	if all(mat[i][pivot] == 0 for i in range(cur, len(mat))):
	# 		continue
	# 	for i in range(cur + 1, len(mat)):
	# 		while mat[i][pivot]:
	# 			q = mat[cur][pivot] // mat[i][pivot]
	# 			for j in range(pivot, l + 1):
	# 				mat[cur][j] -= q * mat[i][j]
	# 			mat[cur], mat[i] = mat[i], mat[cur]
	# 	print(f"{cur = }")
	# 	print(f"{mat[cur] = }")
	# 	cur += 1
	# print(f"Matrix")
	# for row in mat:
	# 	print(row)

"""
n * s
= p*q*r*(inv(p, q*r) + p) mod n^2
= p*n + p*inv(p,q*r)*q*r mod n^2


p*s = 1+p^2 mod q*r
n*s = q*r(1 + p^2) mod (q*r)^2
"""