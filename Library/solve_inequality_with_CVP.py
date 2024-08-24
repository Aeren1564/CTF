from sage.all import *
proof.all(False)

# Bounds are represented by closed intervals
def solve_inequality_with_CVP(M, lower_bound, upper_bound):
	mat, lb, ub = matrix(QQ, M), vector(QQ, lower_bound), vector(QQ, upper_bound)
	assert mat.nrows() > 0
	n, m = mat.nrows(), mat.ncols()
	assert len(lower_bound) == m and len(upper_bound) == m
	assert all(lower_bound[i] <= upper_bound[i] for i in range(m))

	coef = [QQ(max(abs(lower_bound[i]), abs(upper_bound[i]))) for i in range(m)]
	for i in range(n):
		for j in range(m):
			if coef[j]:
				mat[i, j] = QQ(mat[i, j]) / coef[j]
	target_vector = vector(QQ, [(0 if coef[i] == 0 else QQ(lower_bound[i] + upper_bound[i]) / 2 / coef[i]) for i in range(m)])

	mat = mat.LLL()
	G = mat.gram_schmidt()[0]
	diff = target_vector
	for i in reversed(range(G.nrows())):
		diff -=  mat[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	target_vector -= diff

	for j in range(m):
		target_vector[j] *= coef[j]
		if target_vector[j] < lower_bound[j] or upper_bound[j] < target_vector[j]:
			print(f"<WARNING - solve_inequality_with_CVP> Inequality does not hold for {j = }")

	return target_vector

"""
Tested on
- RaRCTF2021/crypto/snore
- CrewCTF2024/crypto/Read between the lines
"""