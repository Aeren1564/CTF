# Given is an elliptic curve E over GF(q) given by the Weierstrass equation Y^2 = X^3 + a*X + b
# We're given an oracle which accepts the X-coordinate of a point P in E, and outputs the X-coordinate of s*P for some fixed secret integer s, but the oracle does not check that such point P exist for given coordinate
# Note that all such point belongs to any of the curve Y^2 = X^3 + a*t^2*X + b*t^3 for non-square t, called the "twisted curve", and they're all of the same order
# Returns a list of possible (s mod m) along with m which is the lcm of the order of the initial curve and the twisted curve
def ECDLP_invalid_curve_attack_single_coordinate(q: int, a: int, b: int, multiply_by_secret, use_initial_curve = True):
	import math
	from sage.all import GF, EllipticCurve, factor, CRT, is_prime
	F = GF(q)
	a, b = F(a), F(b)
	rems, mods = [], []
	def process_for_twist(t):
		EC = EllipticCurve(F, [a * t**2, b * t**3])
		print(f"[INFO]<ECDLP_invalid_curve_attack_single_coordinate> Curve with twist {t} is of order {EC.order()} with factorization {factor(EC.order())}")
		if is_prime(EC.order()):
			p = EC.gen(0)
		else:
			p = EC.gen(0) * math.prod(p for p, e in factor(EC.order()) if p > 2**40)
		cand_sp = EC.lift_x(F(multiply_by_secret(p.x() / t)) * t)
		rem = []
		for sp in [cand_sp, -cand_sp]:
			print(f"[INFO]<ECDLP_invalid_curve_attack_single_coordinate> solving ECDLP with {sp} over the base {p}")
			rem.append(sp.log(p))
		rems.append(rem)
		mods.append(p.order())
	if use_initial_curve:
		process_for_twist(1)
	while True:
		t = F.random_element()
		if not t.is_square():
			process_for_twist(t)
			break
	rem = []
	for r0 in rems[0]:
		for r1 in rems[1]:
			if (r := CRT([r0, r1], mods)) is not None:
				rem.append(r)
	return rem, math.lcm(mods[0], mods[1])
