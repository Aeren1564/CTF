# Source
# - https://gist.github.com/stla/d771e0a8c351d16d186c79bc838b6c48
# - https://math.stackexchange.com/questions/2644640/
# Used in the homomorphism C/lambda -> EC: z -> (wp(z) : wp'(z) : 1) between a complex torus and an elliptic curve
def generate_weierstrass_p_from_g2_and_g3(g2, g3, precision: int = 200, derivative: int = 0):
	import mpmath
	mpmath.mp.dps = precision
	from mpmath import jtheta, pi, exp, sqrt, polyroots, agm, log
	assert derivative >= 0
	r1, r2, r3 = polyroots([4, 0, -g2, -g3])
	e3 = r3
	a, b, c = sqrt(r1 - r3), sqrt(r1 - r2), sqrt(r2 - r3)
	w1 = None
	if abs(a + b) < abs(a - b):
		b *= -1
	if abs(a + c) < abs(a - c):
		c *= -1
	if abs(c + 1j * b) < abs(c - 1j * b):
		e3 = r1
		a = sqrt(r3 - r1)
		b = sqrt(r3 - r2)
		c = sqrt(r2 - r1)
		w1 = 1 / agm(1j * b, c)
	else:
		w1 = 1 / agm(a, b)
	w3 = 1j / agm(a, c)
	q = exp(1j * pi * w3 / w1)
	wp0 = lambda z: e3 + (pi * jtheta(2, 0, q) * jtheta(3, 0, q) * jtheta(4, z / w1, q) / (pi * w1 * jtheta(1, z / w1, q)))**2
	f = jtheta(1, 0, q, 1)**3 / (jtheta(2, 0, q) * jtheta(3, 0, q) * jtheta(4, 0, q))
	wp1 = lambda z: -2*(1 / w1)**3 * jtheta(2, z / w1, q) * jtheta(3, z / w1, q) * jtheta(4, z / w1, q) * f / jtheta(1, z / w1, q)**3
	if derivative == 0:
		return wp0
	if derivative == 1:
		return wp1
	# p'^2   = 4p^3 - g2p - g3
	# p''    = 6p^2 - g2/2
	# p'''   = 12pp'
	# p''''  = 120 p^3 - 18 g2 p - 12 g3
	# p''''' = 360 p^2 p' - 18 g2 p'
	# ...
	coef = [-g2 / 2, mpmath.mpf(0), mpmath.mpf(6)]
	for d in range(3, derivative + 1):
		if d % 2 == 0:
			coef_next = [mpmath.mpf(0) for _ in range(len(coef) + 2)]
			for i in range(len(coef)):
				coef_next[i] -= g2 / 2 * coef[i]
				coef_next[i + 2] += 6 * coef[i]
				if i >= 1:
					coef_next[i - 1] -= i * coef[i] * g3
					coef_next[i] -= i * coef[i] * g2
					coef_next[i + 2] += i * coef[i] * 4
			coef = coef_next
		else:
			coef = [i * coef[i] for i in range(1, len(coef))]
	if derivative % 2 == 0:
		def wp(z):
			res = mpmath.mpf(0)
			x = wp0(z)
			for c in reversed(coef):
				res = res * x + c
			return res
		return wp
	else:
		def wp(z):
			res = mpmath.mpf(0)
			x = wp0(z)
			for c in reversed(coef):
				res = res * x + c
			return res * wp1(z)
		return wp
def generate_weierstrass_p_from_w1_and_w2(w1, w2, precision: int = 200, derivative: int = 0):
	from mpmath import jtheta, pi, exp, sqrt, polyroots, agm, log
	assert w2.imag * w1.real >= w1.imag * w2.real
	ratio = w2 / w1
	assert ratio.imag > 0
	q = exp(1j * pi * ratio)
	j2, j3 = jtheta(2, 0, q), jtheta(3, 0, q)
	g2 = 4 / 3 * (pi / 2 / w1)**4 * (j2**8 - (j2 * j3)**4 + j3**8)
	g3 = 8 / 27 * (pi / 2 / w1)**6 * (j2**12 - ((3 / 2 * j2**8 * j3**4) + (3 / 2 * j2**4 * j3**8)) + j3**12)
	return generate_weierstrass_p_from_g2_and_g3(g2, g3, precision, derivative)
def generate_weierstrass_p_from_tau(tau, precision: int = 200, derivative: int = 0):
	return generate_weierstrass_p_from_w1_and_w2(1.0, tau, precision, derivative)

if __name__ == "__main__":
	eps = pow(10, -5)
	def is_close(x, y):
		return abs(x - y) <= eps
	def test_wp_from_g_value(g2, g3, derivative, z, expected):
		assert is_close(generate_weierstrass_p_from_g2_and_g3(g2, g3, derivative = derivative)(z), expected)
	def test_wp_from_g_differential_equation(g2, g3, z):
		wp = [generate_weierstrass_p_from_g2_and_g3(g2, g3, derivative = d)(z) for d in range(6)]
		assert is_close(wp[1]**2, 4*wp[0]**3 - g2 * wp[0] - g3)
		assert is_close(wp[2], 6*wp[0]**2 - g2 / 2)
		assert is_close(wp[3], 12 * wp[0] * wp[1])
		assert is_close(wp[4], 120 * wp[0]**3 - 18 * g2 * wp[0] - 12 * g3)
		assert is_close(wp[5], (360 * wp[0]**2 - 18 * g2) * wp[1])
	def test_wp_from_w_value(w1, w2, z, expected):
		assert is_close(generate_weierstrass_p_from_w1_and_w2(w1, w2)(z), expected)
	def test_wp_from_tau_value(tau, z, expected):
		assert is_close(generate_weierstrass_p_from_tau(tau)(z), expected)
	for args in [
		(5 - 3j, 2 - 7j, 0, 1 + 1j, -0.117722596733725 + 0.543400126978109j),
		(-5 + 3j, 2 + 7j, 0, 1 + 1j, -1.36964875245851 - 2.51228593126988j),
		(5 + 3j, 2 + 7j, 1, 1 + 1j, -1.78040154378359 + 0.213468471404325j)
	]:
		test_wp_from_g_value(*args)
	for args in [
		(5 + 3j, 2 + 7j, 1 + 1j)
	]:
		test_wp_from_g_differential_equation(*args)
	for args in [
		(1 + 4j, 1 + 15j, 1 + 1j, 0.0076936368424553 - 0.498821838483149j)
	]:
		test_wp_from_w_value(*args)
	for args in [
		(1 + 4j, 1 + 1j, -0.430565782630798 - 3.62705469588323e-16j)
	]:
		test_wp_from_tau_value(*args)