from sage.all import *
proof.all(False)

# Solve system of inequalities by reducing it to the shortest vector problem (SVP)
class inequality_solver_with_SVP:
	# n integral variables x[0], ..., x[-1] where x[i] is within the closed range [var_low[i], var_high[i]]
	def __init__(self, var_low : list, var_high : list):
		assert len(var_low) == len(var_high)
		assert all(var_low[i] <= var_high[i] for i in range(len(var_low)))
		self.n = len(var_low)
		self.var_low = list(map(int, var_low))
		self.var_high = list(map(int, var_high))
		self.coefs = []
		self.lows = []
		self.highs = []
		self.mods = []
	# Add inequality low <= coef[0] * x[0] + ... + coef[-1] * x[-1] + t * mod <= high
	# Solver will try finding solutions which is close to (low + high) / 2
	def add_inequality(self, coef : list, low : int, high : int, mod = 0):
		assert len(coef) == self.n
		assert low <= high
		self.coefs.append(list(map(int, coef)))
		self.lows.append(int(low))
		self.highs.append(int(high))
		self.mods.append(int(mod))
	# Add equality coef[0] * x[0] + ... + coef[-1] * x[-1] + t * mod = value
	def add_equality(self, coef : list, value : int, mod = 0):
		self.add_inequality(coef, value, value, mod)
	# Try different construction if # of estimated solutions (by Gaussian heuristic) is too large
	def solve(self, print_lattice = False):
		print(f"[STARTED] <inequality_solver_with_SVP>")
		n, m = self.n, len(self.coefs)
		mat = identity_matrix(ZZ, n).augment(matrix(ZZ, self.coefs).T)
		low, high = self.var_low + self.lows, self.var_high + self.highs
		for i in range(m):
			if self.mods[i] == 0:
				continue
			mat = mat.stack(vector(ZZ, [self.mods[i] if n + i == j else 0 for j in range(n + m)]))
		mat *= 2
		low = [2 * x for x in low]
		high = [2 * x for x in high]
		# Set the middle of the range to 0
		mat = mat.augment(vector(ZZ, [0] * mat.nrows()))
		mat = mat.stack(vector(ZZ, [-(low[i] + high[i]) // 2 for i in range(n + m)] + [1]))
		low.append(1), high.append(1)
		# Estimate the number of solutions with the Gaussian herustic
		nr, nc = mat.dimensions()
		if nr != nc:
			print(f"[INFO] <inequality_solver_with_SVP> Aborting Gaussian heurstic: non-square matrix {nr} != {nc}")
		else:
			det = mat.determinant()
			if det == 0:
				print(f"[INFO] <inequality_solver_with_SVP> Aborting Gaussian heurstic: zero determinant")
			else:
				cnt = 1
				for l, h in zip(low, high):
					cnt *= h - l + 1
				print(f"[INFO] <inequality_solver_with_SVP> Expected number of solutions: {int(round(cnt / det)) + 1}")
		# Scale up the coefficients so that each components of vector has similar size of ranges, run LLL, then scale back down
		tot = 1
		multiplier = []
		for j in range(nc):
			multiplier.append(high[j] - low[j] + 1)
			tot = lcm(tot, multiplier[-1])
		multiplier = [tot // x for x in multiplier]
		for i in range(nr):
			for j in range(nc):
				mat[i, j] *= multiplier[j]
		mat = mat.LLL()
		for i in range(nr):
			for j in range(nc):
				mat[i, j] //= multiplier[j]
		ret = []
		for row in mat:
			if not 0 <= row[-1] <= 1:
				continue
			if print_lattice:
				print(f"[INFO] {row = }")
			assigned_value = [int(row[i] + (low[i] + high[i]) // 2 * row[-1]) // 2 for i in range(n)]
			equation_value = [int(row[i] + (low[i] + high[i]) // 2 * row[-1]) // 2 for i in range(n, n + m)]
			if any(not self.var_low[i] <= assigned_value[i] <= self.var_high[i] for i in range(n)):
				continue
			if any(not self.lows[i] <= equation_value[i] <= self.highs[i] for i in range(m)):
				continue
			ret.append((assigned_value, equation_value))
		if len(ret) == 0:
			print(f"[WARNING] <inequality_solver_with_SVP> No solutions")
		elif len(ret) >= 2:
			print(f"[WARNING] <inequality_solver_with_SVP> Multiple solutions")
		print(f"[FINISHED] <inequality_solver_with_SVP>")
		return ret

"""
Tested on
- CrewCTF2024/crypto/Read between the lines
- ImaginaryCTF2024/crypto/notitle
- RaRCTF2021/crypto/snore
"""