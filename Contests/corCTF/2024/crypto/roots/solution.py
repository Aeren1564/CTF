from CTF_Library import *

Decimal = RealField(6072)
with open("output.txt") as file:
	output = eval(file.read())

k = 2**6000

solver = inequality_solver_with_SVP([-2**200] * 4, [2**200] * 4)
solver.add_inequality([int(k * output[i]) for i in range(4)], -2**300, 2**300)
coef = solver.solve()[0][0]

solver = inequality_solver_with_SVP([0] * 4, [2**64 - 1] * 4)
solver.add_equality(coef, 0)
res_a = vector(ZZ, solver.solve()[0][0])
basis = matrix(ZZ, coef).right_kernel(basis = "LLL").basis_matrix()

res = []
for multiplier in itertools.product(range(-4, 5), repeat = 3):
	cur = res_a + sum(multiplier[i] * basis[i] for i in range(3))
	if 0 <= min(list(cur)) and max(list(cur)) < 2**64:
		assert vector(ZZ, coef) * cur == 0
		res.append(cur)

for a in res:
	for b in res:
		for c in res:
			flag = b"".join(long_to_bytes(x ^ y ^ z) for x, y, z in zip(a, b, c))
			if flag.startswith(b"corctf{"):
				print(flag)
				exit(0)

"""
p < q < r: 128-bit primes

a, b, c: list of 64-bit integers
0 <= i < 4
a[i] * sqrt(p) + b[i] * sqrt(q) + c[i] * sqrt(r) = output[i]

sum(coef[i] * k * output[i]) = 0
"""