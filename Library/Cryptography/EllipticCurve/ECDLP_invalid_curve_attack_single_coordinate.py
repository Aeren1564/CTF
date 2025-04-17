# Given is an elliptic curve E over GF(p) given by the Weierstrass equation Y^2 = X^3 + a*X + b
# We're given an oracle which accepts the X-coordinate of a point P on E, and outputs the X-coordinate of s*P for some fixed secret integer s, but the oracle does not check that such point P exist for given coordinate
# Note that all such point belongs to any of the curve Y^2 = X^3 + a*t^2*X + b*t^3 for non-square t, called the "twisted curve", and they're all of the same order
# Returns a list of pairs (r, m) where at least one of them satisfies s = r mod m
def ECDLP_invalid_curve_attack_single_coordinate(p: int, a: int, b: int, multiply_by_secret, use_initial_curve = True, threshold: int = 2**40, threshold2: int = 2**50):
	import math
	import itertools
	from sage.all import GF, EllipticCurve, factor, CRT, is_prime
	from ECDLP_prime_power_mod import ECDLP_prime_power_mod
	assert is_prime(p)
	F = GF(p)
	a, b = F(a), F(b)
	rems, mods = [], []
	def process_for_twist(t):
		EC = EllipticCurve(F, [a * t**2, b * t**3])
		print(f"[INFO]<ECDLP_invalid_curve_attack_single_coordinate> Curve with twist {t} is of order {EC.order()} with factorization {factor(EC.order())}")
		p = EC.gen(0)
		cand_sp = EC.lift_x(F(multiply_by_secret(p.x() / t)) * t)
		for sp in [cand_sp, -cand_sp]:
			print(f"[INFO]<ECDLP_invalid_curve_attack_single_coordinate> solving ECDLP with {sp} over the base {p}")
			r, m = ECDLP_prime_power_mod(p, 1, [a, b], p.xy(), sp.xy(), threshold, threshold2)
			rem.append(r)
			if len(rems) == len(mods):
				mods.append(m)
			else:
				assert mods[-1] == m
		rems.append(rem)
	if use_initial_curve:
		process_for_twist(1)
	while True:
		t = F.random_element()
		if not t.is_square():
			process_for_twist(t)
			break
	rem = []
	for rs in itertools.product(rems):
		assert len(rs) == len(mods)
		if (r := CRT(rs, mods)) is not None:
			rem.append(r)
	return rem, math.lcm(mods)
