from sage.all import *
proof.all(False)

class twin_prime_generator:
	def __init__(self, max_bit = 2, candidate_count = 10**6):
		self.max_bit = max_bit
		self.set_of_primes = Primes()
		self.primes = [Integer(2)]
		self.product_of_primes = Integer(2)
		self.candidate_count = candidate_count
		self.candidates = []
		self._extend_prime_list(self.max_bit)
	def _generate_candidates(self):
		from random import getrandbits
		self.candidates = [getrandbits(self.max_bit) for _ in range(self.candidate_count)]
	def _extend_prime_list(self, bit : int):
		if self.max_bit >= bit:
			return
		while self.max_bit < bit:
			self.max_bit <<= 1
		while self.product_of_primes.bit_length() < self.max_bit:
			self.primes.append(self.set_of_primes.next(self.primes[-1]))
			self.product_of_primes *= self.primes[-1]
		self._generate_candidates()
	# Returns an nbit-bit prime p where p+2 is also a prime
	def get_twin_prime(self, nbit : int):
		if nbit == 2:
			return 3
		assert nbit >= 3
		self._extend_prime_list(nbit)
		v = 1
		for p in self.primes:
			v *= p
			if v.bit_length() > nbit - 30 - nbit.bit_length():
				break
		while True:
			for x in self.candidates:
				x = (x >> self.max_bit - nbit) // v * v
				if (x - 1).bit_length() == nbit and is_pseudoprime(x - 1) and is_pseudoprime(x + 1):
					if not is_prime(x - 1):
						print(f"[INFO] <twin_prime_generator> Found counter example for is_pseudoprime: {x - 1}")
						exit(-1)
					if not is_prime(x + 1):
						print(f"[INFO] <twin_prime_generator> Found counter example for is_pseudoprime: {x + 1}")
						exit(-1)
					return int(x - 1)
			self._generate_candidates()
