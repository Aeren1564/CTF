from sage.all import *
proof.all(False)

# UNTESTED
# Solve truncated homogeneous LCG over finite field over GF(_p) defined by _min_poly
# Assume that _truncated is really close to the actual LCG outputs
def solve_truncated_homogeneous_LCG(_a, _p, _truncated, _min_poly = [-1, 1]):
	a = [int(x) for x in copy(_a)]
	p = copy(_p)
	truncated = [int(x) for x in copy(_truncated)]
	min_poly = [int(x) for x in copy(_min_poly)]

	dim = len(min_poly) - 1
	assert dim > 0
	assert len(truncated) % dim == 0
	assert len(a) == dim

	n = len(truncated) // dim

	lattice = []
	lattice.append([p] + [0] + [0] + [0] * (3 * n - 3))
	lattice.append([0] + [p] + [0] + [0] * (3 * n - 3))
	lattice.append([0] + [0] + [p] + [0] * (3 * n - 3))
	
	PR, X = PolynomialRing(ZZ, 'X').objgen()
	min_poly = PR(min_poly)
	a = PR(a)

	for i in range(1, n):
		alpha = [list(a**i % min_poly), list(a**i * X % min_poly), list(a**i * X**2 % min_poly)]
		for j in range(3):
			row = [0] * (3 * n)
			row[0] = int(alpha[0][j])
			row[1] = int(alpha[1][j])
			row[2] = int(alpha[2][j])
			row[3 * i + j] = -1
			lattice.append(row)

	lattice = matrix(ZZ, lattice).LLL()
	k = vector(ZZ, [round(sum([lattice[i, j] * truncated[j] for j in range(3 * n)]) / p) for i in range(3 * n)])

	rem = lattice.solve_right(p * k - lattice * vector(ZZ, truncated))
	res = [int(truncated[i] + rem[i]) for i in range(0, 3 * n)]

	FF = FiniteField(p**dim, modulus = min_poly, names = ['Z'])
	for i in range(0, 3 * n - 3, 3):
		x = FF([res[i], res[i + 1], res[i + 2]])
		x_next = FF([res[i + 3], res[i + 4], res[i + 5]])
		assert x * FF(a) == x_next

	return res