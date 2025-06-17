from CTF_Library import *
import string

ct = bytes.fromhex("142d35c86db4e4bb82ca5965ca1d6bd55c0ffeb35c8a5825f00819821cd775c4c091391f5eb5671b251f5722f1b47e539122f7e5eadc00eee8a6a631928a0c14c57c7e05b6575067c336090f85618c8e181eeddbb3c6e177ad0f9b16d23c777b313e62b877148f06014e8bf3bc156bf88eedd123ba513dfd6fcb32446e41a5b719412939f5b98ffd54c2b5e44f4f7a927ecaff337cddf19fa4e38cbe01162a1b54bb43b0678adf2801d893655a74c656779f9a807c3125b5a30f4800a8")

class XorshiftStream:
	def __init__(self, key: int):
		self.state = key % 2**64

	def _next(self):
		self.state = (self.state ^ (self.state << 13)) % 2**64
		self.state = (self.state ^ (self.state >> 7)) % 2**64
		self.state = (self.state ^ (self.state << 17)) % 2**64
		return self.state

	def encrypt(self, data: bytes):
		ct = b""
		for i in range(0, len(data), 8):
			pt_block = data[i : i + 8]
			ct += (int.from_bytes(pt_block, "little") ^ self._next()).to_bytes(8, "little")[: len(pt_block)]
		return ct

class sym_stream:
	def __init__(self):
		self.state = [2**i for i in range(64)]
	@staticmethod
	def _lshift(state, amt):
		return [0] * amt + state[: -amt]
	@staticmethod
	def _rshift(state, amt):
		return state[amt :] + [0] * amt
	@staticmethod
	def _xor(statel, stater):
		return [statel[i] ^ stater[i] for i in range(64)]
	def next(self):
		self.state = self._xor(self.state, self._lshift(self.state, 13))
		self.state = self._xor(self.state, self._rshift(self.state, 7))
		self.state = self._xor(self.state, self._lshift(self.state, 17))
		return self.state[:]

stream = sym_stream()
solver = linear_equation_solver_GF2(64)
n = len(ct) // 3
for i in range(0, 2 * n - 8, 8):
	state = stream.next()
	x = int.from_bytes(ct[i : i + 8], "little")
	for j in range(0, 64, 8):
		assert solver.add_equation_if_consistent(state[j + 5], x >> j + 5 & 1 ^ 1)
		assert solver.add_equation_if_consistent(state[j + 4] ^ state[j + 6], (x >> j + 4 ^ x >> j + 6) & 1 ^ 1)
		assert solver.add_equation_if_consistent(state[j + 7], x >> j + 7 & 1)

assignment, basis = solver.solve()

for mask in range(2**len(basis)):
	seed = assignment
	for i, b in enumerate(basis):
		if mask >> i & 1:
			seed ^= b
	key = XorshiftStream(seed).encrypt(ct[: 2 * n])
	key += bytes.fromhex(key.decode())
	flag = XorshiftStream(seed).encrypt(xor(ct, key))
	if b"Alpaca{" in flag:
		print(flag)
		exit(0)
