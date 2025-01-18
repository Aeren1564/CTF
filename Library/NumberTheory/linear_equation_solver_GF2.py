class linear_equation_solver_GF2:
	def __init__(self, n : int):
		assert 0 <= n
		self.n = n
		self.equations_and_outputs = []
		self._valid = True
		self._unprocessed = []
	@staticmethod
	def _reduce(basis, v):
		for b in basis:
			v = min(v, v ^ b)
		return v
	def _flush(self):
		if not self._valid or len(self._unprocessed) == 0:
			return
		from concurrent.futures import ThreadPoolExecutor
		self._unprocessed = [self.equations_and_outputs[:]] + [[v] for v in self._unprocessed]
		while len(self._unprocessed) >= 2:
			print(f"[linear_equation_solver_GF2] flushing {len(self._unprocessed)} groups")
			if len(self._unprocessed) % 2 == 1:
				self._unprocessed.append([])
			n = len(self._unprocessed)
			unprocessed_next = [[] for _ in range(n // 2)]
			def merge(i):
				merged = self._unprocessed[i][:]
				for v in self._unprocessed[i + 1]:
					v = self._reduce(merged, v)
					if v == 0:
						continue
					if v == 1:
						return None
					for i in range(len(merged)):
						merged[i] = min(merged[i], merged[i] ^ v)
					merged.append(v)
				return merged[:]
			with ThreadPoolExecutor() as executor:
				for i, merged in zip(range(0, n, 2), executor.map(merge, range(0, n, 2))):
					if merged == None:
						self._valid = False
					unprocessed_next[i >> 1] = merged
			self._unprocessed = unprocessed_next
		self.equations_and_outputs, self._unprocessed = self._unprocessed[0], []
	# Check whether the equations added so far are consistent
	def valid(self):
		self._flush()
		return self._valid
	# equation is represented as a bitmask
	# flushes unprocessed equations
	def consistent(self, equation : int, output : int):
		assert 0 <= equation < 2**self.n and 0 <= output <= 1
		if not self.valid():
			return False
		return self._reduce(self.equations_and_outputs, equation << 1 | output) != 1
	# equation is represented as a bitmask
	# no flush
	def add_equation(self, equation : int, output : int):
		assert 0 <= equation < 2**self.n and 0 <= output <= 1
		self._unprocessed.append(equation << 1 | output)
	# equation is represented as a bitmask
	# flushes unprocessed equations
	def add_equation_if_consistent(self, equation : int, output : int):
		assert 0 <= equation < 2**self.n and 0 <= output <= 1
		if not self.valid():
			return False
		v = self._reduce(self.equations_and_outputs, equation << 1 | output)
		if v == 0:
			return True
		if v == 1:
			return False
		for i in range(len(self.equations_and_outputs)):
			self.equations_and_outputs[i] = min(self.equations_and_outputs[i], self.equations_and_outputs[i] ^ v)
		self.equations_and_outputs.append(v)
		return True
	# Returns (An assignment A, a basis B for solution set)
	# i.e. # of solutions is 2**len(B) and all solution can uniquely be represented as A + sum(S) where S is a subset of B
	def solve(self):
		if not self.valid():
			return None
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