class symbolic_mersenne_twister:
	W, N, M = 32, 624, 397
	A = 0x9908B0DF
	U, D = 11, 0xFFFFFFFF
	S, B = 7, 0x9D2C5680
	T, C = 15, 0xEFC60000
	L = 18
	F = 1812433253
	def __init__(self, init_state = None, init_index = None):
		if init_state == None:
			init_state = [[1 << self.W * i + j for j in range(self.W)] for i in range(self.N)]
		if init_index == None:
			init_index = self.N
		assert len(init_state) == self.N and all(len(s) == self.W for s in init_state)
		assert 0 <= init_index <= self.N
		self.state = init_state
		self.index = init_index
		self._uint_call_count = 0
	@staticmethod
	def _xor(a, b):
		return [x ^ y for x, y in zip(a, b)]
	@staticmethod
	def _and(a, x):
		return [v if x >> i & 1 else 0 for i, v in enumerate(a)]
	@staticmethod
	def _shiftr(a, x):
		return a[x : ] + [0] * x
	@staticmethod
	def _shiftl(a, x):
		return [0] * x + a[ : -x]
	# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L120
	def genrand_uint(self):
		self._uint_call_count += 1
		if self.index >= self.N:
			for k in range(self.N):
				y = self.state[(k + 1) % self.N][ : -1] + self.state[k][-1 : ]
				z = [y[0] if self.A >> i & 1 else 0 for i in range(self.W)]
				self.state[k] = self._xor(self.state[(k + self.M) % self.N], self._shiftr(y, 1))
				self.state[k] = self._xor(self.state[k], z)
			self.index = 0
		y = self.state[self.index]
		y = self._xor(y, self._shiftr(y, self.U))
		y = self._xor(y, self._and(self._shiftl(y, self.S), self.B))
		y = self._xor(y, self._and(self._shiftl(y, self.T), self.C))
		y = self._xor(y, self._shiftr(y, self.L))
		self.index += 1
		return y[:]
	# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L471
	def getrandbits(self, n):
		assert 0 <= n
		if n == 0:
			return []
		if n <= self.W:
			return self.genrand_uint()[-n : ]
		arr = []
		while n > 0:
			r = self.genrand_uint()
			if n < self.W:
				r = r[-n :]
			arr.append(r)
			n -= self.W
		return [x for r in arr for x in r]
	# https://github.com/python/cpython/blob/main/Lib/random.py#L288
	def getrandbytes(self, n):
		return self.getrandbits(8 * n)
	# https://github.com/python/cpython/blob/ebf6d13567287d04683dab36f52cde7a3c9915e7/Modules/_randommodule.c#L187-L193
	# Returns equation for random() * 2**53, which will be an integer in range [0, 2**53)
	def random(self):
		a, b = self.genrand_uint(), self.genrand_uint()
		return b[6:] + a[5:]
	def uint_call_count(self):
		return self._uint_call_count

"""
Tested on
- idekCTF2024/crypto/Seedy
"""