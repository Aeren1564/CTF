from sage.all import *
proof.all(False)

# Source: https://github.com/rkm0959/Inequality_Solving_with_CVP/blob/main/solver.sage
# Given n variables x_0, \cdots, x_{n-1} and m inequalties lower_bound[j] <= \sum_{i=0}^{N-1} M[i][j] * x[i] <= upper_bound[j],
# Try finding a feasible solution with CVP
def solve_inequality_with_CVP(M, lower_bound, upper_bound):
	print(f"<INFO - solve_inequality_with_CVP> Started")
	mat, lb, ub = matrix(QQ, M), vector(QQ, lower_bound), vector(QQ, upper_bound)
	assert mat.nrows() > 0
	n, m = mat.nrows(), mat.ncols()
	assert len(lower_bound) == m and len(upper_bound) == m
	assert all(lower_bound[i] <= upper_bound[i] for i in range(m))

	if n == m:
		det = abs(mat.determinant())
		if det == 0:
			print(f"<INFO - solve_inequality_with_CVP> Zero determinant")
		else:
			# Gaussian heuristic
			solution_count = 1
			for l, u in zip(lower_bound, upper_bound):
				solution_count *= u - l
			solution_count /= det
			print(f"<INFO - solve_inequality_with_CVP> Expected number of solutions: {int(solution_count) + 1}")
	else:
		print(f"<INFO - solve_inequality_with_CVP> {n} != {m}")

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
			print(f"<WARNING - solve_inequality_with_CVP> Inequality does not hold at index {j}")

	print(f"<INFO - solve_inequality_with_CVP> Finished")
	return target_vector

"""
Tested on
- RaRCTF2021/crypto/snore
- CrewCTF2024/crypto/Read between the lines
"""