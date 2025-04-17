# Given is an elliptic curve E over GF(p) given by the Weierstrass equation Y^2 = X^3 + a*X + b for some integer b
# We're given an oracle which accepts the a point P on E, and outputs s*P for some fixed secret integer s, but the oracle does not check that P belongs to the curve
# Note that the point addition formula does not rely on the parameter b
# Returns a pair {r, m} such that s = r mod m
def ECDLP_invalid_curve_attack(p: int, a: int, multiply_by_secret, required_modulus_size: int, curve_count: int = 1, threshold: int = 2**40):
	import math
	from sage.all import GF, EllipticCurve, factor, CRT, is_prime
	assert 0 <= min(key_bit_length, required_modulus_size, curve_count)
	assert is_prime(p)
	F = GF(p)
	a = F(a)
	r, m = 0, 1
	for b in map(F, range(1, p)):
		if curve_count == 0:
			break
		EC = EllipticCurve(F, [a, b])
		P = EC.gen(0)
		for q, f in factor(P.order()):
			if q >= threshold:
				print(f"[INFO]<ECDLP_invalid_curve_attack> ignoring factor {q}^{f}")
				P *= q**f
		if P.order() < required_modulus_size:
			continue
		curve_count -= 1
		Q = EC(*multiply_by_secret(*P.xy()))
		r, m = CRT([r, Q.log(P)], [m, P.order()])
	else:
		print(f"[ERROR]<ECDLP_invalid_curve_attack_single_coordinate> fail to generate enough curves with modulus equal or greater than {required_modulus_size}")
		assert False
	return r, m
