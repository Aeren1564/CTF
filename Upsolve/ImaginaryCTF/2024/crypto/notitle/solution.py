from CTF_Library import *
from chall import p, magic_op
from output import magic_pi, magic_e, obfuscated_keys, ct, iv

F = GF(p**2, "X")

pi = F(314159)
e = F(271828)
magic_pi = F(magic_pi)
magic_e = F(magic_e)

assert magic_op(magic_pi, p - 1) == 1
assert magic_op(magic_e, p + 1) == 1

factor_minus = Factorization(factor(p - 1, limit = 2**20)[ : -1]).value()
factor_plus = Factorization(factor(p + 1, limit = 2**20)[ : -1]).value()
rem_minus = (p - 1) // factor_minus
rem_plus = (p + 1) // factor_plus

def phi(x):
	return [x + y for y in sqrt(x**2 - 1, all = True)]

assert all(x**(p - 1) == 1 for x in phi(pi))
assert all(x**(p + 1) == 1 for x in phi(e))

for phi_magic_pi in phi(magic_pi):
	for phi_pi in phi(pi):
		for phi_magic_e in phi(magic_e):
			for phi_e in phi(e):
				h_minus = (phi_magic_pi**rem_minus).log(phi_pi**rem_minus, order = factor_minus)
				assert phi_magic_pi**rem_minus == (phi_pi**rem_minus)**h_minus
				h_plus = (phi_magic_e**rem_plus).log(phi_e**rem_plus, order = factor_plus)
				assert phi_magic_e**rem_plus == (phi_e**rem_plus)**h_plus
				h = 2**10000
				for h1 in [h_minus, -h_minus]:
					for h2 in [h_plus, -h_plus]:
						h = min(h, CRT([h1, h2], [factor_minus, factor_plus]))
				if h.bit_length() > 512:
					continue
				print(f"{h = }")
				assert magic_op(GF(p)(pi), h) == GF(p)(magic_pi)
				assert magic_op(GF(p)(e), h) == GF(p)(magic_e)
				assert h % 4 == 0 and h // 4 % 2 == 1

				inv = pow(h // 4, -1, p * p - 1)
				assert(h * inv % (p * p - 1) == 4)

				candidates = []
				for obfuscated_key in map(GF(p), obfuscated_keys):
					enc_key = magic_op(obfuscated_key, inv)
					X = polygen(GF(p))
					cur = list(map(int, (magic_op(X, 4) - enc_key).roots(multiplicities = False)))
					assert len(cur) > 0
					assert all(magic_op(GF(p)(x), h) == obfuscated_key for x in cur)
					cur = [x for x in cur if x < p - x]
					candidates.extend(cur)

				n = len(candidates)
				solver = inequality_solver_with_SVP([-1] * n, [1] * n)
				solver.add_inequality(candidates, 1, 2**128, p)

				key = solver.solve()[0][1][-1].to_bytes(16)
				cipher = AES.new(key, AES.MODE_CTR, nonce = iv)
				flag = cipher.decrypt(ct)
				print(f"{flag = }")
				exit(0)
