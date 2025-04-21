# Based on https://mathoverflow.net/questions/249872/generating-dataset-of-strong-pseudoprimes
# Returns a tuple containing the pseudoprime n = p_1 * p_2 along with its factors
def generate_strong_pseudoprime_2(bases: list, min_bit_length: int, count : int, check):
	from sage.all import Zmod, is_prime, CRT
	import os
	from math import lcm
	from multiprocessing import Pool
	assert len(bases) > 0 and all(is_prime(p) for p in bases)
	assert min_bit_length >= 0
	def miller(n, b):
		r, s = 0, n - 1
		while s % 2 == 0:
			r += 1
			s //= 2
		x = b**s
		if x == 1 or x == n - 1:
			return True
		for _ in range(r - 1):
			x *= x
			if x == n - 1:
				return True
		else:
			return False
	def miller_light(p, q, b):
		return pow(int(b), p // 2, q) + 1 == q
	rem, mod = [5], [8]
	for b in sorted(bases):
		if b == 2:
			continue
		if mod[-1] == b:
			continue
		if b == 3 or b == 5:
			for r in Zmod(b):
				if r != 0 and 2 * r - 1 != 0 and (2 * r - 1).is_square():
					rem.append(int(r))
					mod.append(b)
					break
		else:
			for x in Zmod(b):
				if x != 0 and 2 * x - 1 != 0 and not x.is_square() and (2 * x - 1).is_square():
					rem.append(int(x))
					mod.append(b)
					break
		assert mod[-1] == b
	rem = int(CRT(rem, mod))
	mod = lcm(*mod)
	p = 2**(min_bit_length // 2) // mod * mod + rem
	q = 2 * p + 1
	res = []
	while len(res) < count:
		p, q = p + mod, q + 2 * mod
		if all(miller(p * q, b) if b in (3, 5) else miller_light(p, q, b) for b in map(Zmod(p * q), reversed(bases))) and check(p * q, p, q):
			res.append((p * q, p, q))
	return res

# Source: https://github.com/jvdsn/crypto-attacks/blob/master/attacks/pseudoprimes/miller_rabin.py
# Based on "Constructing Carmichael Numbers which are Strong Pseudoprimes to Several Bases" by François Arnault
# Returns a list of tuples of length count containing the pseudoprime n = p_1 * p_2 * p_3 along with its factors
def generate_strong_pseudoprime_3(bases: list, min_bit_length: int, count : int, is_valid : None):
	from sage.all import is_prime, next_prime, kronecker, CRT
	from math import gcd, lcm
	assert len(bases) > 0 and all(is_prime(p) for p in bases)
	assert min_bit_length >= 0
	assert count > 0
	if is_valid is None:
		is_valid = lambda x, p1, p2, p3: True
	def _generate_s(A, k):
		S = []
		for a in A:
			Sa = set()
			for p in range(1, 4 * a, 2):
				if kronecker(a, p) == -1:
					Sa.add(p)
			Sk = []
			for ki in k:
				assert gcd(ki, 4 * a) == 1
				Sk.append({pow(ki, -1, 4 * a) * (s + ki - 1) % (4 * a) for s in Sa})
			S.append(Sa.intersection(*Sk))
		return S
	def _backtrack(S, A, X, M, i):
		if i == len(S):
			return CRT(X, M), lcm(*M)
		M.append(4 * A[i])
		for za in S[i]:
			X.append(za)
			try:
				CRT(X, M)
				z, m = _backtrack(S, A, X, M, i + 1)
				if z is not None and m is not None:
					return z, m
			except ValueError:
				pass
			X.pop()
		M.pop()
		return None, None
	A = sorted(bases)
	k2 = int(next_prime(A[-1]))
	k3 = int(next_prime(k2))
	while True:
		X = [pow(-k3, -1, k2), pow(-k2, -1, k3)]
		M = [k2, k3]
		S = _generate_s(A, M)
		z, m = _backtrack(S, A, X, M, 0)
		if z and m:
			i = (2**(min_bit_length // 3)) // m
			res = []
			while len(res) < count:
				p1 = int(z + i * m)
				p2 = k2 * (p1 - 1) + 1
				p3 = k3 * (p1 - 1) + 1
				if is_prime(p1) and is_prime(p2) and is_prime(p3) and is_valid(p1 * p2 * p3, p1, p2, p3):
					res.append((p1 * p2 * p3, p1, p2, p3))
				i += 1
			return res
		else:
			k3 = int(next_prime(k3))
