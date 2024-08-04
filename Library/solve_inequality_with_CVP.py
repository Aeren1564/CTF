from sage.all import *
proof.all(False)

def solve_inequality_with_CVP(M, lower_bound, upper_bound):
	mat, lb, ub = matrix(QQ, M), vector(QQ, lower_bound), vector(QQ, upper_bound)
	assert mat.nrows() > 0
	n, m = mat.nrows(), mat.ncols()
	assert len(lower_bound) == m and len(upper_bound) == m
	assert all(upper_bound[i] - lower_bound[i] >= 1 for i in range(m))

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