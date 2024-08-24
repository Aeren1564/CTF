class mersenne_twister_breaker:
	from symbolic_mersenne_twister import symbolic_mersenne_twister
	from linear_equation_solver_F2 import linear_equation_solver_F2
	recovery_mode = None
	W, N, M, R = 32, 624, 397, 31
	A = 0x9908B0DF
	U, D = 11, 0xFFFFFFFF
	S, B = 7, 0x9D2C5680
	T, C = 15, 0xEFC60000
	L = 18
	F = 1812433253
	@staticmethod
	def _sanitize(x, w):
		assert isinstance(x, (int, str))
		if isinstance(x, int):
			assert 0 <= x < 2**w
			x = "".join([str(x >> i & 1) for i in range(w)])
		assert len(x) == w
		assert all(c in "01?" for c in x)
		return x
	# https://stackered.com/blog/python-random-prediction/
	@staticmethod
	def recover_seed_array_from_state(state, subtract_indices):
		def _init_genrand(seed):
			MT = [0] * 624
			MT[0] = seed & 0xFFFFFFFF
			for i in range(1, 624):
				MT[i] = 0x6c078965 * (MT[i - 1] ^ MT[i - 1] >> 30) + i & 0xFFFFFFFF
			return MT
		def _recover_kj_from_Ji(ji, ji1, i):
			return ji - (_init_genrand(19650218)[i] ^ (ji1 ^ ji1 >> 30) * 1664525) & 0xFFFFFFFF
		def _recover_Ji_from_Ii(Ii, Ii1, i):
			return (Ii + i ^ (Ii1 ^ Ii1 >> 30) * 1566083941) & 0xFFFFFFFF
		s = [0] * 624
		for i in range(623, 2, -1):
			s[i] = _recover_Ji_from_Ii(state[i], state[i - 1], i)
		s[0] = s[623]
		s[1] = _recover_Ji_from_Ii(state[1], state[623], 1)
		s[2] = _recover_Ji_from_Ii(state[2], s[1], 2)
		seed = [0] * 624
		for i in range(623, 2, -1):
			seed[i - 1] = _recover_kj_from_Ji(s[i], s[i - 1], i)
		seed[0] = 0
		s1_old = (2194844435 ^ (19650218 ^ 19650218 >> 30) * 1664525) & 0xFFFFFFFF
		seed[1] = _recover_kj_from_Ji(s[2], s1_old, 2)
		seed[623] = s[1] - (s1_old ^ (s[0] ^ s[0] >> 30) * 1664525) & 0xFFFFFFFF
		if subtract_indices:
			seed = [(2**32 + e - i) % 2**32 for i, e in enumerate(seed)]
		return seed
	# Goal is to recover the initial state
	def init_state(self, init_index):
		assert 1 <= init_index <= self.N
		self.n, self.recovery_mode = self.W * self.N, 0
		self.solver = self.linear_equation_solver_F2(n = self.n)
		self.init_index = init_index
		self.twister = self.symbolic_mersenne_twister(init_index = self.init_index)
	# Goal is to recover the 32bit integer seed
	def init_seed(self):
		self.n, self.recovery_mode = self.W * self.N, 1
		self.solver = self.linear_equation_solver_F2(n = self.n)
		for i in range(self.W):
			assert self.solver.add_equation_if_consistent(1 << i, int(i == self.W - 1))
		self.init_index = self.N
		self.twister = self.symbolic_mersenne_twister(init_index = self.init_index)
	# Goal is to recover the byte seed
	def init_byteseed(self):
		self.n, self.recovery_mode = self.W * self.N, 2
		self.solver = self.linear_equation_solver_F2(n = self.n)
		for i in range(self.W):
			assert self.solver.add_equation_if_consistent(1 << i, int(i == self.W - 1))
		self.init_index = self.N
		self.twister = self.symbolic_mersenne_twister(init_index = self.init_index)
	def add_equation_on_current_state(self, equation, output):
		assert self.recovery_mode in range(3)
		assert 0 <= equation < 2**self.n and 0 <= output <= 1
		eqs = 0
		for i in range(self.n):
			if equation >> i & 1:
				eqs ^= self.twister.state[i]
		assert self.solver.add_equation_if_consistent(eqs, output)
	# if x is a string, it must of length self.W consisting of characters in "01?", representing values in little endian order
	def setrand_uint(self, x):
		assert self.recovery_mode in range(3)
		x = self._sanitize(x, self.W)
		eqs = self.twister.genrand_uint()
		for i, v in enumerate(reversed(eqs)):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eq, int(x[i]))
	# if x is a string, it must of length n consisting of characters in "01?", representing values in little endian order
	def setrandbits(self, n, x):
		assert self.recovery_mode in range(3)
		x = self._sanitize(x, n)
		eqs = self.twister.getrandbits(n)
		for i, eq in enumerate(reversed(eqs)):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eq, int(x[i]))
	# if x is a string, it must of length 8 * n consisting of characters in "01?", representing values in little endian order
	def setrandbytes(self, n, x):
		assert self.recovery_mode in range(3)
		self.setrandbits(8 * n, x)
	def recover(self):
		assert self.recovery_mode in range(3)
		assignment, basis = self.solver.solve()
		if len(basis) != 0:
			print("<WARNING - mersenne_twister_breaker> Non-unique solution")
		state = [assignment >> self.W * i & self.D for i in range(self.N)] + [self.init_index]
		if self.recovery_mode == 0:
			return (3, tuple(state), None)
		elif self.recovery_mode == 1:
			return self.recover_seed_array_from_state(state, False)[2]
		else:
			from hashlib import sha512
			# Assumes that len(seed) + 64(512/8) + 12 <= 624 * 4 (in bytes)
			recovered = bytes([x >> 8 * i & 0xFF for x in reversed(self.recover_seed_array_from_state(state, True)) for i in range(3, -1, -1)])
			pref, h = recovered[ : -64], recovered[-64 : ]
			for l in range(len(pref) - 12):
				if sha512(pref[-l : ]).digest()[ : -8] == h[ : -8]:
					return pref[-l : ]
			assert False

if __name__ == "__main__":
	import random

	def test_recover_seed_from_state():
		r = random.Random()
		seed = 923534439
		r.seed(seed)
		breaker = mersenne_twister_breaker()
		recovered = breaker.recover_seed_array_from_state(r.getstate()[1])[2]
		assert recovered == seed
		print(f"[test_recover_seed_from_state] finished")

	def test_recover_seed():
		r = random.Random()
		seed = 923534439
		r.seed(seed)
		breaker = mersenne_twister_breaker()
		breaker.init_seed()
		for i in range(624):
			print(f"[test_recover_seed] {i = }")
			breaker.setrandbits(32, r.getrandbits(32))
		assert breaker.recover() == seed
		print(f"[test_recover_seed] Finished")

	def test_recover_byteseed():
		r = random.Random()
		byteseed = b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZTest0_Test1_Test2_Test3_Test4_Test5"
		r.seed(byteseed)
		breaker = mersenne_twister_breaker()
		breaker.init_byteseed()
		for i in range(624):
			print(f"[test_recover_byteseed] {i = }")
			breaker.setrandbits(32, r.getrandbits(32))
		recovered = breaker.recover()
		assert recovered == byteseed
		print(f"[test_recover_byteseed] Finished")

	test_recover_seed_from_state()
	test_recover_seed()
	test_recover_byteseed()

"""
Tested on
- idekCTF2024/crypto/Seedy
"""