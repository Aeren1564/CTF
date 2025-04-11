"""
Elliptic curve discrete logarithm problem over prime power modulus

See
- https://github.com/elikaski/ECC_Attacks
- https://github.com/soon-haari/my-ctf-challenges/tree/main/2025-codegate/crypto-thesewalls

Let E be an elliptic curve over Zmod(p^e) given by the Weierstrass equation
 Y^2 = X^3 + coef[0] * X + coef[1], if len(coef) = 2
 Y^2 + coef[0] * XY + coef[2] * Y = X^3 + coef[1] * X^2 + coef[3] * X + coef[4], otherwise

Let P = (Px, Py) and Q = (Qx, Qy) be points on E such that k*P=Q for some integer k

This function attempts to find a pair of integers (r, m) such that k = r mod m, and m is as large as possible, by iterating over all attacks on vulnerable curve known to me

Current list of attacks
1. singular curve attack (for e=1)
2. Prime power curve attack (using EC(Zmod(p**e)) ~ EC(GF(p)) x Zmod(p**(e-1)))
3. Smart attack (for EC with order = p)
4. MOV attack (for EC with high embedding degree, such as a supersingular curve)
5. quadratic twist attack for supersingular curve with a=0 or b=0
"""
def ECDLP_prime_power_mod(p: int, e: int, coef: list, P: tuple, Q: tuple, threshold: int = 2**40, threshold2: int = 2**50):
	assert threshold >= -1 and threshold2 >= 0
	# threshold == -1 turns off everything except for the prime power check
	p, e, (Px, Py), (Qx, Qy) = int(p), int(e), map(int, P), map(int, Q)
	coef = list(map(int, coef))
	import time
	from math import lcm
	from sage.all import is_prime, CRT, ZZ, Zmod, GF, Qp, EllipticCurve, factor
	from EC_coordinate_normalizer import EC_coordinate_normalizer
	assert p >= 5 and is_prime(p) and e >= 1
	mod = p**e
	if len(coef) == 2:
		coef = [0, 0, 0, coef[0], coef[1]]
	assert len(coef) == 5
	normalizer = EC_coordinate_normalizer(Zmod(mod), coef)
	coef = list(map(int, normalizer.get_coef()))
	Px, Py = map(int, normalizer.map(Px, Py))
	Qx, Qy = map(int, normalizer.map(Qx, Qy))
	desc = -16 * (4 * coef[0]**3 + 27 * coef[1]**2) % p
	F, R = GF(p), Zmod(p**e)
	attack_list = []
	if desc == 0:
		def update_with_singular_curve_attack():
			if threshold == -1 or e != 1: # I don't know how to solve prime power case
				return 0, 1
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_singular_curve_attack begin")
			x = F["X"].gen()
			f = x**3 + coef[0]*x + coef[1]
			roots = f.roots()
			if len(roots) == 1:
				alpha = roots[0][0]
				u = (Px - alpha) / Py
				v = (Qx - alpha) / Qy
				return int(F(v / u)), p
			elif len(roots) == 2:
				if roots[0][1] == 2:
					alpha = roots[0][0]
					beta = roots[1][0]
				elif roots[1][1] == 2:
					alpha = roots[1][0]
					beta = roots[0][0]
				else:
					assert False
				t = (alpha - beta).sqrt()
				u = (Py + t * (Px - alpha)) / (Py - t * (Px - alpha))
				v = (Qy + t * (Qx - alpha)) / (Qy - t * (Qx - alpha))
				return v.log(u), p**2
			else:
				assert False
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_singular_curve_attack end")
		attack_list += [update_with_singular_curve_attack]
	else:
		ECF = EllipticCurve(F, coef)
		ECR = EllipticCurve(R, coef)
		PF, QF, PR, QR = ECF(Px, Py), ECF(Qx, Qy), ECR(Px, Py), ECR(Qx, Qy)
		p_order = PF.order()
		curve_order = ECF.order()
		assert QF.weil_pairing(PF, p_order) == 1, "[ERROR]<ECDLP_prime_power_mod>, P and Q must be linearly dependent"
		def update_with_prime_power():
			if e == 1 or curve_order % p == 0:
				return 0, 1
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_prime_power begin")
			# EC(Zmod(p**e)) ~ EC(GF(p)) x Zmod(p**(e-1))
			# Deal with Zmod(p**(e-1)) part with EC(Qp(p))
			ECQp = ECR.change_ring(Qp(p))
			PQp, QQp = ECQp(PR) * curve_order, ECQp(QR) * curve_order
			k = int(Zmod(p**(e-1))((QQp.x() / QQp.y()) / (PQp.x() / PQp.y())))
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_prime_power end")
			return k, p**(e-1)
		def update_with_small_factor():
			if threshold == -1:
				return 0, 1
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_small_factor begin")
			large_factors = 1
			for q, f in factor(p_order):
				if q >= threshold:
					print(f"[INFO]<ECDLP_prime_power_mod> update_with_small_factor ignoring factor {q}^{f}")
					large_factors *= q**f
			k = (large_factors * QF).log(large_factors * PF)
			assert k * large_factors * PF == large_factors * QF
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_small_factor end")
			return k, (large_factors * PF).order()
		def update_with_Smart_attack():
			if threshold == -1 or curve_order != p:
				return 0, 1
			# Anomalous curve -> Smart attack
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_Smart_attack begin")
			import random
			EQp = EllipticCurve(Qp(p), [x + random.randrange(1, p) * p for x in coef])
			for PQp in EQp.lift_x(ZZ(PF.x()), all = True):
				if F(PQp.y()) == PF.y():
					break
			for QQp in EQp.lift_x(ZZ(QF.x()), all = True):
				if F(QQp.y()) == QF.y():
					break
			PQp, QQp = PQp * p, QQp * p
			k = int(F((QQp.x() / QQp.y()) / (PQp.x() / PQp.y())))
			assert k * PF == QF
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_Smart_attack end")
			return k, PF.order()
		def update_with_MOV_attack():
			if threshold == -1:
				return 0, 1
			for d in range(1, 7):
				if pow(p, d, p_order) == 1:
					break
			else:
				return 0, 1
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_MOV_attack begin with embedding degree {d}")
			large_factors = 1
			for q, f in list(factor(p - 1)) + list(factor((p**d - 1) / (p - 1))):
				if q >= threshold2:
					print(f"[INFO]<ECDLP_prime_power_mod> update_with_MOV_attack ignoring factor {q}^{f}")
					large_factors *= q**f
			EC2 = EllipticCurve(GF(p**d), coef)
			P2, Q2 = EC2(Px, Py) * large_factors, EC2(Qx, Qy) * large_factors
			opt_order = -1
			opt_order_R2 = None
			for _ in range(100):
				R2 = EC2.random_element()
				R2 = (R2.order() // P2.order()) * R2
				if R2.order() == P2.order() and R2.weil_pairing(P2, P2.order()) != 1:
					alpha = R2.weil_pairing(P2, P2.order())
					if opt_order < alpha.multiplicative_order():
						opt_order = alpha.multiplicative_order()
						opt_order_R2 = R2
			if opt_order_R2 == None:
				return 0, 1
			alpha = P2.weil_pairing(opt_order_R2, opt_order_R2.order())
			beta = Q2.weil_pairing(opt_order_R2, opt_order_R2.order())
			assert P2.order() % alpha.multiplicative_order() == 0
			loss = P2.order() // alpha.multiplicative_order()
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_MOV_attack {loss = }")
			start_time = time.time()
			k = beta.log(alpha)
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_MOV_attack discrete log took {time.time() - start_time} seconds")
			assert k * loss * P2 == loss * Q2
			print(f"[INFO]<ECDLP_prime_power_mod> update_with_MOV_attack end")
			return k, alpha.multiplicative_order()
		attack_list += [update_with_prime_power, update_with_small_factor, update_with_Smart_attack, update_with_MOV_attack]
	r, m = 0, 1
	for attack in attack_list:
		rr, mm = attack()
		r, m = CRT([r, rr], [m, mm]), lcm(m, mm)
	return int(r), int(m)

if __name__ == "__main__":
	from sage.all import is_prime, CRT, Zmod, GF, Qp, EllipticCurve
	def test_conversion():
		print(f"[INFO]<ECDLP_prime_power_mod> test_conversion begin")
		from sage.all import GF, EllipticCurve
		p, e = 1000000007, 1
		coef = [123, 456, 23423, 8182, 3291]
		EC = EllipticCurve(GF(p), coef)
		P = EC.lift_x(GF(p)(3))
		k = 1233423
		Q = k * P
		r, m = ECDLP_prime_power_mod(p, e, coef, P.xy(), Q.xy())
		assert 0 <= r < m
		assert k % m == r
		assert r == k
		print(f"[INFO]<ECDLP_prime_power_mod> test_conversion end\n")
	def test_singular():
		print(f"[INFO]<ECDLP_prime_power_mod> test_singular begin")
		from custom_elliptic_curve import custom_elliptic_curve
		p, e = 229054522729978652250851640754582529779, 1 # not sure how to deal with high e for singular curve
		coef = [-75, -250]
		EC = custom_elliptic_curve(p, coef)
		P = EC(97396093570994028423863943496522860154, 2113909984961319354502377744504238189)
		k = 12324342554345523452132592398117171**max(1, e - 1)
		Q = k * P
		r, m = ECDLP_prime_power_mod(p, e, coef, P.xy(), Q.xy())
		assert 0 <= r < m
		assert k % m == r
		assert r == k
		print(f"[INFO]<ECDLP_prime_power_mod> test_singular end\n")
	def test_power():
		print(f"[INFO]<ECDLP_prime_power_mod> test_power begin")
		p, e = 74894047922780452080480621188147614680859459381887703650502711169525598419741, 3
		coef = [22457563127094032648529052905270083323161530718333104214029365341184039143821, 82792468191695528560800352263039950790995753333968972067250646020461455719312]
		EC = EllipticCurve(Zmod(p**e), coef)
		P = EC(201395103510950985196528886887600944697931024970644444173327129750000389064102542826357168547230875812115987973230106228243893553395960867041978131850021580112077013996963515239128729448812815223970675917812499157323530103467271226, 217465854493032911836659600850860977113580889059985393999460199722148747745817726547235063418161407320876958474804964632767671151534736727858801825385939645586103320316229199221863893919847277366752070948157424716070737997662741835)
		k = 123243425543455234521325923981171711233142435231413413423421341341424232352454245424253
		Q = k * P
		r, m = ECDLP_prime_power_mod(p, e, coef, P.xy(), Q.xy())
		assert 0 <= r < m
		assert k % m == r
		assert r == k
		print(f"[INFO]<ECDLP_prime_power_mod> test_power end\n")
	def test_anomalous():
		print(f"[INFO]<ECDLP_prime_power_mod> test_anomalous begin")
		p, e = 0xa15c4fb663a578d8b2496d3151a946119ee42695e18e13e90600192b1d0abdbb6f787f90c8d102ff88e284dd4526f5f6b6c980bf88f1d0490714b67e8a2a2b77, 1 # not sure how to deal with high e for anomalous curve
		coef = [0x5e009506fcc7eff573bc960d88638fe25e76a9b6c7caeea072a27dcd1fa46abb15b7b6210cf90caba982893ee2779669bac06e267013486b22ff3e24abae2d42, 0x2ce7d1ca4493b0977f088f6d30d9241f8048fdea112cc385b793bce953998caae680864a7d3aa437ea3ffd1441ca3fb352b0b710bb3f053e980e503be9a7fece]
		R = Zmod(p**e)
		E = EllipticCurve(R, coef)
		P = E.lift_x(R(9872341))
		k = 189213912839910219309139439134911**max(1, e - 2)
		Q = k * P
		r, m = ECDLP_prime_power_mod(p, e, coef, P.xy(), Q.xy())
		assert 0 <= r < m
		assert k % m == r
		assert r == k
		print(f"[INFO]<ECDLP_prime_power_mod> test_anomalous end\n")
	def test_low_embedding_degree():
		print(f"[INFO]<ECDLP_prime_power_mod> test_low_embedding_degree begin")
		p, e = 1331169830894825846283645180581, 5
		coef = [-35, 98]
		assert (p**2 - 1) % EllipticCurve(GF(p), coef).order() == 0
		R = Zmod(p**e)
		E = EllipticCurve(R, coef)
		P = E.lift_x(R(479691812266187139164535778017))
		k = 1331169830894825846273645180581**max(1, e - 1)
		Q = k * P
		r, m = ECDLP_prime_power_mod(p, e, coef, P.xy(), Q.xy())
		assert 0 <= r < m
		assert k % m == r
		assert r == k
		print(f"[INFO]<ECDLP_prime_power_mod> test_low_embedding_degree end\n")
	for testcase in [
		test_conversion,
		test_singular,
		test_power,
		test_anomalous,
		test_low_embedding_degree,
	]:
		testcase()