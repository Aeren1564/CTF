# Source: https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/singular_curve.py
"""
Solves the discrete logarithm problem on a singular curve y^2 = x^3 + a2 * x^2 + a4 * x + a6.
p: the prime of the curve base ring
a2: the a2 parameter of the curve
a4: the a4 parameter of the curve
a6: the a6 parameter of the curve
Gx: the base point x value
Gy: the base point y value
Px: the point multiplication result x value
Py: the point multiplication result y value
Returns m such that m * P == Q
"""
def EC_singular_curve_attack(p: int, a2, a4, a6, P, Q):
	a2, a4, a6, Px, Py, Qx, Qy = int(a2), int(a4), int(a6), int(tuple(P)[0]), int(tuple(P)[1]), int(tuple(Q)[0]), int(tuple(Q)[1])
	from sage.all import GF, is_prime
	if not is_prime(p):
		print(f"[ERROR] <EC_singular_curve_attack> {p} is not a prime")
		assert False
	desc = (18 * a2 * a4 * a6 - 4 * a2**3 * a6 + a2**2 * a4**2 - 4 * a4**3 - 27 * a6**2) % p
	if desc != 0:
		print(f"[ERROR] <EC_singular_curve_attack> The curve is non-singular with descriminant {desc} != 0")
		assert False
	def on_curve(x, y):
		return y * y % p == (x**3 + a2 * x**2 + a4 * x + a6) % p
	if not on_curve(Px, Py):
		print(f"[ERROR] <EC_singular_curve_attack> P({Px}, {Py}) is not on the curve")
		assert False
	if not on_curve(Qx, Qy):
		print(f"[ERROR] <EC_singular_curve_attack> Q({Qx}, {Qy}) is not on the curve")
		assert False
	x = GF(p)["x"].gen()
	f = x**3 + a2 * x**2 + a4*x + a6
	roots = f.roots()
	if len(roots) == 1:
		print(f"[INFO] <EC_singular_curve_attack> The singular point is a cusp")
		alpha = roots[0][0]
		u = (Px - alpha) / Py
		v = (Qx - alpha) / Qy
		return int(v / u)
	elif len(roots) == 2:
		print(f"[INFO] <EC_singular_curve_attack> The singular point is a node")
		if roots[0][1] == 2:
			alpha = roots[0][0]
			beta = roots[1][0]
		elif roots[1][1] == 2:
			alpha = roots[1][0]
			beta = roots[0][0]
		else:
			print(f"[ERROR] <EC_singular_curve_attack> There's something wrong with the implementation")
			assert False
		t = (alpha - beta).sqrt()
		u = (Py + t * (Px - alpha)) / (Py - t * (Px - alpha))
		v = (Qy + t * (Qx - alpha)) / (Qy - t * (Qx - alpha))
		return int(v.log(u))
	else:
		print(f"[ERROR] <EC_singular_curve_attack> There's something wrong with the implementation")
		assert False

"""
Tested on
- IronCTF2024/crypto/Backdoor
"""