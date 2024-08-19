# Simulate python random module
class symbolic_mersenne_twister:
	N = 624
	M = 397
	A = 0x9908b0df
	# Note that when seeded, init_index is N and state[0] is 2**31
	def __init__(self, init_index):
		self.state = [ [ (1 << (32 * i + (31 - j))) for j in range(32) ] for i in range(624)]
		self.index = init_index
	@staticmethod
	def _xor(a, b):
		return [x ^ y for x, y in zip(a, b)]
	@staticmethod
	def _and(a, x):
		return [ v if (x >> (31 - i)) & 1 else 0 for i, v in enumerate(a) ]
	@staticmethod
	def _shiftr(a, x):
		return [0] * x + a[:-x]
	@staticmethod
	def _shiftl(a, x):
		return a[x:] + [0] * x
	def get32bits(self):
		if self.index >= self.N:
			for kk in range(self.N):
				y = self.state[kk][:1] + self.state[(kk + 1) % self.N][1:]
				z = [ y[-1] if (self.A >> (31 - i)) & 1 else 0 for i in range(32) ]
				self.state[kk] = self._xor(self.state[(kk + self.M) % self.N], self._shiftr(y, 1))
				self.state[kk] = self._xor(self.state[kk], z)
			self.index = 0
		y = self.state[self.index]
		y = self._xor(y, self._shiftr(y, 11))
		y = self._xor(y, self._and(self._shiftl(y, 7), 0x9d2c5680))
		y = self._xor(y, self._and(self._shiftl(y, 15), 0xefc60000))
		y = self._xor(y, self._shiftr(y, 18))
		self.index += 1
		return y
	# returns 'bit' leading bits
	def getrandbits(self, bit):
		return self.get32bits()[:bit]

"""
Tested on
- idekCTF2024/crypto/Seedy
"""