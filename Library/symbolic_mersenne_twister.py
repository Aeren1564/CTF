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
			init_state = [[(1 << (self.W * i + (self.W - 1 - j))) for j in range(self.W)] for i in range(self.N)]
		if init_index == None:
			init_index = self.N
		assert len(init_state) == self.N and all(len(s) == self.W for s in init_state)
		assert 0 <= init_index <= self.N
		self.state = init_state
		self.index = init_index
	@staticmethod
	def _xor(a, b):
		return [x ^ y for x, y in zip(a, b)]
	@staticmethod
	def _and(a, x):
		return [v if (x >> (31 - i)) & 1 else 0 for i, v in enumerate(a)]
	@staticmethod
	def _shiftr(a, x):
		return [0] * x + a[ : -x]
	@staticmethod
	def _shiftl(a, x):
		return a[x : ] + [0] * x
	# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L120
	# Note that it returns in big endian order
	def genrand_uint(self):
		if self.index >= self.N:
			for k in range(self.N):
				y = self.state[k][ : 1] + self.state[(k + 1) % self.N][1 : ]
				z = [y[-1] if self.A >> self.W - 1 - i & 1 else 0 for i in range(self.W)]
				self.state[k] = self._xor(self.state[(k + self.M) % self.N], self._shiftr(y, 1))
				self.state[k] = self._xor(self.state[k], z)
			self.index = 0
		y = self.state[self.index]
		y = self._xor(y, self._shiftr(y, self.U))
		y = self._xor(y, self._and(self._shiftl(y, self.S), self.B))
		y = self._xor(y, self._and(self._shiftl(y, self.T), self.C))
		y = self._xor(y, self._shiftr(y, self.L))
		self.index += 1
		return y
	# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L471
	# Note that it returns in big endian order
	def getrandbits(self, n):
		assert 0 <= n
		if n == 0:
			return []
		if n <= self.W:
			return self.genrand_uint()[ : n]
		arr = []
		while n > 0:
			r = self.genrand_uint()
			if n < self.W:
				r = r[ : n]
			arr.append(r)
			n -= self.W
		return [x for r in reversed(arr) for x in r]
	# https://github.com/python/cpython/blob/main/Lib/random.py#L288
	# Note that it returns in big endian order
	def randbytes(self, n):
		return self.getrandbits(8 * n)

"""
Tested on
- idekCTF2024/crypto/Seedy
"""