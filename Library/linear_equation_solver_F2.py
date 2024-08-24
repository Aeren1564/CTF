class linear_equation_solver_F2:
	def __init__(self, n : int):
		assert 0 <= n
		self.n = n
		self.equations = []
		self.outputs = []
	def reduce(self, equation : int, output : int):
		assert 0 <= equation < 2**self.n and 0 <= output <= 1
		for eq, o in zip(self.equations, self.outputs):
			lsb = eq & -eq
			if equation & lsb:
				equation ^= eq
				output ^= o
		return equation, output
	# equation is represented as a bitmask
	def consistent(self, equation : int, output : int):
		equation, output = self.reduce(equation, output)
		return equation != 0 or output == 0
	# equation is represented as a bitmask
	def add_equation_if_consistent(self, equation : int, output : int):
		equation, output = self.reduce(equation, output)
		if equation == 0:
			if output != 0:
				return False
			return True
		lsb = equation & -equation
		for i in range(len(self.equations)):
			if self.equations[i] & lsb:
				self.equations[i] ^= equation
				self.outputs[i] ^= output
		self.equations.append(equation)
		self.outputs.append(output)
		return True
	# Returns (An assignment A, a basis B for solution set)
	# i.e. # of solutions is 2**len(B) and all solution can uniquely be represented as A + sum(S) where S is a subset of B
	def solve(self):
		assignment, pivot, basis = 0, 0, []
		for i, eq in enumerate(self.equations):
			pivot |= eq & -eq
			if self.outputs[i]:
				assignment |= eq & -eq
		for i in range(self.n):
			if pivot >> i & 1 == 0:
				b = 1 << i
				for eq in self.equations:
					if eq >> i & 1:
						b |= eq & -eq
				basis.append(b)
		for eq, o in zip(self.equations, self.outputs):
			assert (eq & assignment).bit_count() % 2 == o
			assert all((eq & b).bit_count() % 2 == 0 for b in basis)
		return [assignment, basis]

"""
Tested on
- idekCTF2024/crypto/Seedy
"""