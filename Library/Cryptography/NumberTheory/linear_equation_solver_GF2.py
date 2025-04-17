class _bit_vector:
	def __init__(self, data: list, flip: list):
		self.n = len(data)
		assert len(flip) == self.n
		for x in data:
			assert 0 <= x
		for x in flip:
			assert 0 <= x <= 1
		self.data = data[:]
		self.flip = flip[:]
	def copy(self):
		return _bit_vector(self.data[:], self.flip[:])
	def __lshift__(self, x):
		assert 0 <= x <= self.n
		if x == 0:
			return _bit_vector(self.data, self.flip)
		return _bit_vector([0] * x + self.data[:-x], [0] * x + self.flip[:-x])
	def __rshift__(self, x):
		assert 0 <= x <= self.n
		if x == 0:
			return _bit_vector(self.data, self.flip)
		return _bit_vector(self.data[x:] + [0] * x, self.flip[x:] + [0] * x)
	def __xor__(self, x):
		assert isinstance(x, (int, _bit_vector))
		if isinstance(x, int):
			assert 0 <= x < 2**self.n
			flip = self.flip[:]
			for i in range(self.n):
				flip[i] ^= x >> i & 1
			return _bit_vector(self.data, flip)
		else:
			assert self.n == x.n
			return _bit_vector([self.data[i] ^ x.data[i] for i in range(self.n)], [self.flip[i] ^ x.flip[i] for i in range(self.n)])
	def __invert__(self):
		return _bit_vector(self.data, [1 - self.flip[i] for i in range(self.n)])
	def __ilshift__(self, x):
		assert 0 <= x <= len(data)
		self = self << x
		return self
	def __irshift__(self, x):
		assert 0 <= x <= len(data)
		self = self >> x
		return self
	def __ixor__(self, other):
		self = self ^ other
		return self
	def __getitem__(self, i):
		return (self.data[i], self.flip[i])
def make_bit_vectors(ns: list):
	bvs = []
	offset = 0
	for n in ns:
		assert(0 <= n)
		bvs.append(_bit_vector([1 << i for i in range(offset, offset + n)], [0] * n))
		offset += n
	return bvs
class linear_equation_solver_GF2:
	def __init__(self, n : int):
		assert 0 <= n
		self.n = n
		self.equations_and_outputs = []
	def _reduce(self, equation, output : int):
		if not isinstance(equation, int):
			equation, output = equation[0], output ^ equation[1]
		assert isinstance(equation, int)
		assert 0 <= equation < 2**self.n and 0 <= output <= 1
		equation_and_output = equation << 1 | output
		for eq_o in self.equations_and_outputs:
			equation_and_output = min(equation_and_output, equation_and_output ^ eq_o)
		return equation_and_output >> 1, equation_and_output & 1
	# equation is represented as a bitmask
	def consistent(self, equation, output : int):
		equation, output = self._reduce(equation, output)
		return equation != 0 or output == 0
	# equation is represented as a bitmask
	def add_equation_if_consistent(self, equation, output : int):
		equation, output = self._reduce(equation, output)
		if equation == 0:
			if output != 0:
				return False
			return True
		equation_and_output = equation << 1 | output
		for i in range(len(self.equations_and_outputs)):
			self.equations_and_outputs[i] = min(self.equations_and_outputs[i], self.equations_and_outputs[i] ^ equation_and_output)
		self.equations_and_outputs.append(equation_and_output)
		return True
	# Returns (An assignment A, a basis B for solution set)
	# i.e. # of solutions is 2**len(B) and all solution can uniquely be represented as A + sum(S) where S is a subset of B
	def solve(self):
		assignment, pivots, basis = 0, 0, []
		for i, eq_o in enumerate(self.equations_and_outputs):
			pivot = 1 << (eq_o >> 1).bit_length() - 1
			pivots |= pivot
			if eq_o & 1 == 1:
				assignment |= pivot
		for i in range(self.n):
			if pivots >> i & 1 == 0:
				b = 1 << i
				for eq_o in self.equations_and_outputs:
					if eq_o >> i + 1 & 1:
						b |= 1 << (eq_o >> 1).bit_length() - 1
				basis.append(b)
		for eq_o in self.equations_and_outputs:
			eq, output = eq_o >> 1, eq_o & 1
			assert (eq & assignment).bit_count() % 2 == output
			assert all((eq & b).bit_count() % 2 == 0 for b in basis)
		return [assignment, basis]

"""
Tested on
- idekCTF2024/crypto/Seedy
"""