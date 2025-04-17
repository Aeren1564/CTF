"""
Elliptic curve decisional Diffie-Hellman problem over prime power modulus

See
- https://github.com/elikaski/ECC_Attacks
- https://github.com/soon-haari/my-ctf-challenges/tree/main/2025-codegate/crypto-thesewalls

Let E be an elliptic curve over Zmod(p^e) given by the Weierstrass equation
 Y^2 = X^3 + coef[0] * X + coef[1], if len(coef) = 2
 Y^2 + coef[0] * XY + coef[2] * Y = X^3 + coef[1] * X^2 + coef[3] * X + coef[4], otherwise

Let P = (Px, Py) and Q = (Qx, Qy) be points on E such that k*P=Q for some integer k
Let targets be a list of pairs points on E

This function attempts to check if k*R = S for each pair (R, S) in targets
If it returns 0, the real answer is false
If it returns 1, the real answer is true
Otherwise, the answer could be both

Returns None if P and Q are linearly independent
"""
def ECDDHP_prime_power_mod(p: int, e: int, coef: list, P: tuple, Q: tuple, targets: list, threshold: int = 2**40, threshold2: int = 2**50):
	p, e, (Px, Py), (Qx, Qy) = int(p), int(e), map(int, P), map(int, Q)
	targets = [(tuple(map(int, R)), tuple(map(int, S))) for R, S in targets]
	coef = list(map(int, coef))
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
	targets = [(tuple(map(int, normalizer.map(*R))), tuple(map(int, normalizer.map(*S)))) for R, S in targets]
	desc = -16 * (4 * coef[0]**3 + 27 * coef[1]**2) % p
	from ECDLP_prime_power_mod import ECDLP_prime_power_mod
	if desc == 0:
		if e >= 2:
			return [None for _ in targets]
		print(f"[INFO]<ECDDHP_prime_power_mod> singular begin")
		from custom_elliptic_curve import custom_elliptic_curve
		k = ECDLP_prime_power_mod(p, 1, coef, (Px, Py), (Qx, Qy), threshold, threshold2)[0]
		EC = custom_elliptic_curve(p, coef)
		print(f"[INFO]<ECDDHP_prime_power_mod> singular end")
		return [1 if k * EC(*R) == EC(*S) else 0 for R, S in targets]
	else:
		F = GF(p)
		ECF, ECR = EllipticCurve(F, coef), EllipticCurve(Zmod(p**e), coef)
		PF, QF = ECF(Px, Py), ECF(Qx, Qy)
		if QF.weil_pairing(PF, PF.order()) != 1:
			print(f"[WARNING]<ECDDHP_prime_power_mod>, P and Q must be linearly dependent")
			return None
		res = []
		if ECF.order() == p + 1 and (coef[0] % p == 0 or coef[1] % p == 0):
			print(f"[INFO]<ECDDHP_prime_power_mod> updating with quadratic twist begin")
			F2 = GF(p**2)
			ECF2 = ECF.change_ring(F2)
			if coef[0] % p == 0:
				print(f"[INFO]<ECDDHP_prime_power_mod> twisting with cubic root of 1")
				root = F2(1).nth_root(3)
				def distortion_map(P):
					return ECF2(root * P.x(), P.y())
			if coef[1] % p == 0:
				print(f"[INFO]<ECDDHP_prime_power_mod> twisting with square root of -1")
				root = F2(-1).nth_root(2)
				def distortion_map(P):
					return ECF2(-P.x(), root * P.y())
			if e >= 2:
				r0, m0 = ECDLP_prime_power_mod(p, e, coef, (Px, Py), (Qx, Qy), -1, 0)
			for R, S in targets:
				RF, SF = ECF(*R), ECF(*S)
				if ECF2(PF).weil_pairing(distortion_map(SF), p + 1) != ECF2(QF).weil_pairing(distortion_map(RF), p + 1):
					res.append(0)
				elif e == 1:
					res.append(1)
				else:
					r1, m1 = ECDLP_prime_power_mod(p, e, coef, R, S, -1, 0)
					res.append(1 if r0 == r1 else 0)
			print(f"[INFO]<ECDDHP_prime_power_mod> updating with quadratic twist end")
		else:
			print(f"[INFO]<ECDDHP_prime_power_mod> explicit computation begin")
			res = [None for _ in targets]
			for i, (R, S) in enumerate(targets):
				RF, SF = ECF(*R), ECF(*S)
				if SF.weil_pairing(RF, RF.order()) != 1 or SF.weil_pairing(PF, PF.order()) != RF.weil_pairing(QF, QF.order()):
					res[i] = 0
			k = ECDLP_prime_power_mod(p, e, coef, (Px, Py), (Qx, Qy), threshold, threshold2)[0]
			if k * ECR(Px, Py) == ECR(Qx, Qy):
				for i, (R, S) in enumerate(targets):
					if res[i] == None:
						res[i] = (1 if k * ECR(*R) == ECR(*S) else 0)
			print(f"[INFO]<ECDDHP_prime_power_mod> explicit computation end")
		return res

if __name__ == "__main__":
	from sage.all import is_prime, CRT, Zmod, GF, Qp, EllipticCurve
	def test_singular(ans):
		print(f"[INFO]<ECDDHP_prime_power_mod> test_singular begin with {ans = }")
		from custom_elliptic_curve import custom_elliptic_curve
		p, e = 229054522729978652250851640754582529779, 1
		coef = [-75, -250]
		EC = custom_elliptic_curve(p, coef)
		P = EC(97396093570994028423863943496522860154, 2113909984961319354502377744504238189)
		k = 12324342554345523452132592398117171**max(1, e - 1)
		Q = k * P
		R = 1324234553451323423 * Q
		S = (k if ans else 24942399143991349) * R
		assert [ans] == ECDDHP_prime_power_mod(p, e, coef, P.xy(), Q.xy(), [(R.xy(), S.xy())])
		print(f"[INFO]<ECDDHP_prime_power_mod> test_singular end\n")
	def test_anomalous(ans):
		print(f"[INFO]<ECDDHP_prime_power_mod> test_anomalous begin with {ans = }")
		p, e = 0xa15c4fb663a578d8b2496d3151a946119ee42695e18e13e90600192b1d0abdbb6f787f90c8d102ff88e284dd4526f5f6b6c980bf88f1d0490714b67e8a2a2b77, 1
		coef = [0x5e009506fcc7eff573bc960d88638fe25e76a9b6c7caeea072a27dcd1fa46abb15b7b6210cf90caba982893ee2779669bac06e267013486b22ff3e24abae2d42, 0x2ce7d1ca4493b0977f088f6d30d9241f8048fdea112cc385b793bce953998caae680864a7d3aa437ea3ffd1441ca3fb352b0b710bb3f053e980e503be9a7fece]
		R = Zmod(p**e)
		E = EllipticCurve(R, coef)
		P = E.lift_x(R(9872341))
		k = 189213912839910219309139439134911**max(1, e - 1)
		Q = k * P
		R = 1324234553451323423 * Q
		S = (k if ans else 24942399143991349) * R
		assert [ans] == ECDDHP_prime_power_mod(p, e, coef, P.xy(), Q.xy(), [(R.xy(), S.xy())])
		print(f"[INFO]<ECDDHP_prime_power_mod> test_anomalous end\n")
	def test_low_embedding_degree(ans):
		print(f"[INFO]<ECDDHP_prime_power_mod> test_low_embedding_degree begin with {ans = }")
		p, e = 1331169830894825846283645180581, 5
		coef = [-35, 98]
		R = Zmod(p**e)
		E = EllipticCurve(R, coef)
		P = E.lift_x(R(479691812266187139164535778017))
		k = 29618469991922269**max(1, e - 1)
		Q = k * P
		R = 132423 * Q
		S = (k if ans else 24942399143991349) * R
		assert [ans] == ECDDHP_prime_power_mod(p, e, coef, P.xy(), Q.xy(), [(R.xy(), S.xy())])
		print(f"[INFO]<ECDDHP_prime_power_mod> test_low_embedding_degree end\n")
	def test_hypersingular_qudratic_twist_cubic(ans):
		print(f"[INFO]<ECDDHP_prime_power_mod> test_hypersingular_qudratic_twist_cubic begin with {ans = }")
		p, e = 2717597692908121319788497985451, 4
		coef = [59988839927984767712262022881015186528306823080680093817066551387449092966635391654583736371714324230765899668876056205191762535690049456590296016977519955444196107647233071737264095096436949854658419817766417617008402215963718256820349403830936535830427821814691174887502426870436662513573210000832221322398, 101967710743792389969422216712450509569034697830818344524896876130478391402643388132308880397086156977788425616725940825720775848656512466204212492162471675713660761367404158291366066068856768564375952666036454337938403204290723496566781748665353311583138442143621327486984669015180894834194757115816809502955]
		assert EllipticCurve(GF(p), coef).order() == p + 1
		R = Zmod(p**e)
		E = EllipticCurve(R, coef)
		P = E.lift_x(R(479691812266187139164535778017))
		k = 29618469991922269**max(1, e - 1)
		Q = k * P
		R = 1324234553451323423 * Q
		S = (k if ans else 24942399143991349) * R
		assert [ans] == ECDDHP_prime_power_mod(p, e, coef, P.xy(), Q.xy(), [(R.xy(), S.xy())])
		print(f"[INFO]<ECDDHP_prime_power_mod> test_hypersingular_qudratic_twist_cubic end\n")
	def test_hypersingular_qudratic_twist_quadratic(ans):
		print(f"[INFO]<ECDDHP_prime_power_mod> test_hypersingular_qudratic_twist_quadratic begin with {ans = }")
		p, e = 324094280281900209908870811008292068290746348301400744740589987, 5
		coef = [59988839927984767712262022881015186528306823080680093817066551387449092966635391654583736371714324230765899668876056205191762535690049456590296016977519955444196107647233071737264095096436949854658419817766417617008402215963718256820349403830936535830427821814691174887502426870436662513573210000832221322398, 101967710743792389969422216712450509569034697830818344524896876130478391402643388132308880397086156977788425616725940825720775848656512466204212492162471675713660761367404158291366066068856768564375952666036454337938403204290723496566781748665353311583138442143621327486984669015180894834194757115816809502955]
		assert EllipticCurve(GF(p), coef).order() == p + 1
		R = Zmod(p**e)
		E = EllipticCurve(R, coef)
		P = E.lift_x(R(4796918122661871391601))
		k = 29618469991922269**max(1, e - 1)
		Q = k * P
		R = 1324234553451323423 * Q
		S = (k if ans else 24942399143991349) * R
		assert [ans] == ECDDHP_prime_power_mod(p, e, coef, P.xy(), Q.xy(), [(R.xy(), S.xy())])
		print(f"[INFO]<ECDDHP_prime_power_mod> test_hypersingular_qudratic_twist_quadratic end\n")
	for testcase in [
		test_singular,
		test_anomalous,
		test_low_embedding_degree,
		test_hypersingular_qudratic_twist_cubic,
		test_hypersingular_qudratic_twist_quadratic
	]:
		for ans in [
			0,
			1
		]:
			testcase(ans)
