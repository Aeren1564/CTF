from sage.all import *

proof.all(False)

def partition_point(low: int, high: int, pred):
	assert low < high
	while high - low >= 2:
		mid = (low + high) // 2
		if pred(mid):
			low = mid
		else:
			high = mid
	return high

def solve_inequality_with_CVP(M, lower_bound, upper_bound):
	mat, lb, ub = matrix(QQ, M), vector(QQ, lower_bound), vector(QQ, upper_bound)
	assert mat.nrows() > 0
	n, m = mat.nrows(), mat.ncols()
	assert len(lower_bound) == m and len(upper_bound) == m
	assert all(lower_bound[i] < upper_bound[i] for i in range(m))

	coef = [QQ(upper_bound[i] - lower_bound[i]) / 2 for i in range(m)]
	for i in range(n):
		for j in range(m):
			mat[i, j] = QQ(mat[i, j]) / coef[j]
	target_vector = vector(QQ, [1] * m)

	mat = mat.LLL()
	G = mat.gram_schmidt()[0]
	diff = target_vector
	for i in reversed(range(G.nrows())):
		diff -=  mat[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	target_vector -= diff

	for j in range(m):
		target_vector[j] *= coef[j]
		if target_vector[j] < lower_bound[j] or upper_bound[j] <= target_vector[j]:
			print(f"<WARNING> Inequality does not hold for {j = }")

	return target_vector

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