class linear_equation_solver_F2:
	def __init__(self):
		self.equations = []
		self.outputs = []
	# equation is represented as a bitmask
	def add_equation(self, equation : int, output : int):
		assert 0 <= output <= 1
		for eq, o in zip(self.equations, self.outputs):
			lsb = eq & -eq
			if equation & lsb:
				equation ^= eq
				output ^= o
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
	def solve(self):
		res = 0
		for i, eq in enumerate(self.equations):
			if self.outputs[i]:
				# Assume every free variable is 0
				res |= eq & -eq
		# Sanity check
		for eq, o in zip(self.equations, self.outputs):
			assert (eq & res).bit_count() % 2 == o
		return res

"""
Tested on
- idekCTF2024/crypto/Seedy
"""