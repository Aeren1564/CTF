class mersenne_twister_breaker:
	from symbolic_mersenne_twister import symbolic_mersenne_twister
	from Cryptography.LinearAlgebra.linear_equation_solver_GF2 import linear_equation_solver_GF2
	recovery_mode = None
	W, N, M, R = 32, 624, 397, 31
	A = 0x9908B0DF
	U, D = 11, 0xFFFFFFFF
	S, B = 7, 0x9D2C5680
	T, C = 15, 0xEFC60000
	L = 18
	F = 1812433253
	def _sanitize(self, x, w):
		assert isinstance(x, (int, bytes, str))
		if isinstance(x, int):
			assert 0 <= x < 2**w
			x = "".join([str(x >> i & 1) for i in range(w)])
		elif isinstance(x, bytes):
			assert len(x) == w
			w *= 8
			x = "".join([str(x[i >> 3] >> i % 8 & 1) for i in range(w)])
		assert len(x) == w
		assert all(c in "01?" for c in x)
		return x
	# From https://stackered.com/blog/python-random-prediction
	def _unshift_right(self, x, shift):
		res = x
		for i in range(32):
			res = x ^ res >> shift
		return res
	# From https://stackered.com/blog/python-random-prediction
	def _unshift_Left(self, x, shift, mask):
		res = x
		for i in range(32):
			res = x ^ (res << shift & mask)
		return res
	# From https://stackered.com/blog/python-random-prediction
	def untemper(self, v):
		v = self._unshift_right(v, 18)
		v = self._unshift_Left(v, 15, 0xefc60000)
		v = self._unshift_Left(v, 7, 0x9d2c5680)
		v = self._unshift_right(v, 11)
		return v
	# From https://stackered.com/blog/python-random-prediction
	def _invert_step(self, si, si227):
		X = si ^ si227
		mti1 = (X & 0x80000000) >> 31
		if mti1:
			X ^= self.A
		return X << 1 & 0x80000000, mti1 + (X << 1 & 0x7FFFFFFF)
	# From https://stackered.com/blog/python-random-prediction
	# Note that the first state value is never used except for its MSB
	def rewind_state(self, state):
		prev_state = [0] * 624
		s = state[ : ]
		I, I0 = self._invert_step(s[self.N - 1], s[self.M - 1])
		prev_state[self.N - 1] = I
		# this does nothing when working with a known full state, but is important we rewinding more than 1 time
		s[0] = (s[0] & 0x80000000) + I0
		for i in reversed(range(self.N - self.M, self.N - 1)):
			I, I1 = self._invert_step(s[i], s[i - (self.N - self.M)])
			prev_state[i] += I
			prev_state[i + 1] += I1
		for i in reversed(range(self.N - self.M)):
			I, I1 = self._invert_step(s[i], prev_state[i + self.M])
			prev_state[i] += I
			prev_state[i + 1] += I1
		# The LSBs of prev_state[0] do not matter, they are 0 here
		return prev_state[ : ]
	# From https://stackered.com/blog/python-random-prediction
	def recover_seed_array_from_state(self, state, subtract_indices):
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
			seed = [(x - i) % 2**32 for i, x in enumerate(seed)]
		return seed[ : ]
	# Goal is to recover the initial state
	def init_state(self, init_index):
		assert 1 <= init_index <= self.N
		self.n, self.recovery_mode = self.W * self.N, 0
		self.solver = self.linear_equation_solver_GF2(n = self.n)
		self.init_index = init_index
		self.twister = self.symbolic_mersenne_twister(init_index = self.init_index)
	# Goal is to recover the list of all possible integer seeds within range [0, 2^{624-32*3}) in increasing order
	def init_seed(self):
		self.n, self.recovery_mode = self.W * self.N, 1
		self.solver = self.linear_equation_solver_GF2(n = self.n)
		for i in range(self.W):
			assert self.solver.add_equation_if_consistent(1 << i, 1 if i == self.W - 1 else 0)
		self.init_index = self.N
		self.twister = self.symbolic_mersenne_twister(init_index = self.init_index)
	# Goal is to recover the byte seed
	def init_byteseed(self):
		self.n, self.recovery_mode = self.W * self.N, 2
		self.solver = self.linear_equation_solver_GF2(n = self.n)
		for i in range(self.W):
			assert self.solver.add_equation_if_consistent(1 << i, 1 if i == self.W - 1 else 0)
		self.init_index = self.N
		self.twister = self.symbolic_mersenne_twister(init_index = self.init_index)
	def add_equation_on_current_state(self, equation, output):
		assert self.recovery_mode in range(3)
		assert 0 <= equation < 2**self.n and 0 <= output <= 1
		eqs = 0
		for i in range(self.N):
			for j in range(self.W):
				if equation >> self.W * i + j & 1:
					eqs ^= self.twister.state[i][self.W - 1 - j]
		assert self.solver.add_equation_if_consistent(eqs, output)
	# if x is a string, it must of length self.W consisting of characters in "01?"
	def setrand_uint(self, x):
		assert isinstance(x, (int, str))
		assert self.recovery_mode in range(3)
		x = self._sanitize(x, self.W)
		eqs = self.twister.genrand_uint()
		for i, v in enumerate(reversed(eqs)):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eq, int(x[i]))
	# if x is an integer, it is the same as python random.getrandbits
	# if x is a string, it must of length n consisting of characters in "01?"
	def setrandbits(self, n, x):
		assert isinstance(x, (int, str))
		assert self.recovery_mode in range(3)
		x = self._sanitize(x, n)
		eqs = self.twister.getrandbits(n)
		for i, eq in enumerate(reversed(eqs)):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eq, int(x[i]))
	# if x is a bytes, it is the same as python random.randbytes
	# if x is a string, it must of length 8 * n consisting of characters in "01?"
	def setrandbytes(self, n, x):
		assert isinstance(x, (bytes, str))
		assert self.recovery_mode in range(3)
		x = self._sanitize(x, n)
		eqs = self.twister.getrandbits(8 * n)
		for i, eq in enumerate(reversed(eqs)):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eq, int(x[i]))
	def recover(self):
		assert self.recovery_mode in range(3)
		print(f"[INFO] <mersenne_twister_breaker> recovery begin with mode {'state' if self.recovery_mode == 0 else 'int' if self.recovery_mode == 1 else 'byte'}")
		assignment, basis = self.solver.solve()
		if len(basis) != 0:
			print(f"[WARNING] <mersenne_twister_breaker> {2**len(basis)} solutions")
		state = [assignment >> self.W * i & self.D for i in range(self.N)] + [self.init_index]
		if self.recovery_mode == 0:
			return (3, tuple(state), None)
		elif self.recovery_mode == 1:
			recovered = self.recover_seed_array_from_state(state, False)
			seeds = []
			for period in range(1, len(recovered) - 2):
				if recovered[2 + period : -1] != recovered[2 : -1 - period]:
					continue
				seed = 0
				for i in reversed(range(period)):
					seed = seed << 32 | (recovered[i if i >= 2 else period + i] - i + 2**32) % 2**32
				seeds.append(seed)
			return seeds[:]
		else:
			from hashlib import sha512
			# Assumes that len(seed) + 64(512/8) + 12 <= 624 * 4 (in bytes)
			recovered = bytes([x >> 8 * i & 0xFF for x in reversed(self.recover_seed_array_from_state(state, True)) for i in range(3, -1, -1)])
			pref, h = recovered[ : -64], recovered[-64 : ]
			for l in range(len(pref) - 12):
				if sha512(pref[-l : ]).digest()[ : -8] == h[ : -8]:
					return pref[-l : ]
			print("[ERROR] <mersenne_twister_breaker> Failed to recover the seed")
			assert False

if __name__ == "__main__":
	import random

	def test_rewind():
		r = random.Random(12345)
		I = list(random.getstate()[1][:-1])
		breaker = mersenne_twister_breaker()
		S1 = [breaker.untemper(random.getrandbits(32)) for _ in range(624)]
		S2 = [breaker.untemper(random.getrandbits(32)) for _ in range(624)]
		S3 = [breaker.untemper(random.getrandbits(32)) for _ in range(624)]
		I_ = breaker.rewind_state(S1)
		S2_ = breaker.rewind_state(S3)
		S1_ = breaker.rewind_state(S2)
		assert I_[1 : ] == I[1 : ]
		assert S1_[1 : ] == S1[1 : ]
		assert S2_[1 : ] == S2[1 : ]
		I_ = breaker.rewind_state(breaker.rewind_state(breaker.rewind_state(S3)))
		assert I_ == I
		print(f"[test_rewind] Succeeded")

	def test_recover_seed_from_state():
		r = random.Random()
		seed = 923534439
		r.seed(seed)
		breaker = mersenne_twister_breaker()
		recovered = breaker.recover_seed_array_from_state(r.getstate()[1], False)[2]
		assert recovered == seed
		print(f"[test_recover_seed_from_state] Succeeded")

	def test_recover_seed():
		r = random.Random()
		seed0 = 0x00353443_93423242_33489534_89012300_23491239_04528478_73277234_72348945_38927835
		seed1 = 0x0035343a_93423239_3348952b_890122f7_23491230_0452846f_7327722b_7234893c_3892782c_00353443_93423242_33489534_89012300_23491239_04528478_73277234_72348945_38927835
		r.seed(seed1)
		breaker = mersenne_twister_breaker()
		breaker.init_seed()
		for i in range(312):
			print(f"[test_recover_seed] {i = }")
			breaker.setrandbits(64, r.getrandbits(64))
		state = r.getstate()[1]
		for i in [1, 3, 10]:
			for j in range(0, 32, 3):
				breaker.add_equation_on_current_state(1 << 32 * i + j, state[i] >> j & 1)
		for i in range(10):
			breaker.setrandbits(12, r.getrandbits(12))
		recovered = breaker.recover()
		assert seed0 in recovered and seed1 in recovered
		print(f"[test_recover_seed] Succeeded")

	def test_recover_byteseed():
		r = random.Random()
		byteseed = b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZTest0_Test1_Test2_Test3_Test4_Test5"
		r.seed(byteseed)
		breaker = mersenne_twister_breaker()
		breaker.init_byteseed()
		for i in range(156):
			print(f"[test_recover_byteseed] {i = }")
			breaker.setrandbytes(32, r.randbytes(32))
		state = r.getstate()[1]
		for i in [1, 3, 10]:
			for j in range(0, 32, 3):
				breaker.add_equation_on_current_state(1 << 32 * i + j, state[i] >> j & 1)
		for i in range(10):
			breaker.setrandbytes(3, r.randbytes(3))
		recovered = breaker.recover()
		assert recovered == byteseed
		print(f"[test_recover_byteseed] Succeeded")

	test_rewind()
	test_recover_seed_from_state()
	test_recover_seed()
	test_recover_byteseed()

"""
Tested on
- idekCTF2024/crypto/Seedy
"""