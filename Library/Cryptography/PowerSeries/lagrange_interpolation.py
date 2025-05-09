def lagrange_interpolation(R, points):
	if len(points) == 0:
		return R(0)
	points = [(R(x), R(y)) for x, y in points]
	n = len(points)
	dif = [R(points[0][1])] * n
	dp, dp_next = [points[i][1] for i in range(n)], [0] * n
	for j in range(1, n):
		for i in range(j, n):
			dp_next[i] = (dp[i] - dp[i - 1]) / (points[i][0] - points[i - j][0])
		dp, dp_next = dp_next, dp
		dif[j] = R(dp[j])
	var = R['X'].gen()
	res = dif[n - 1]
	for i in range(n - 2, -1, -1):
		res = res * (var - points[i][0]) + dif[i]
	return res

def lagrange_interpolation_on_interval(R, x_l, x_r, ys, take = None):
	assert x_l <= x_r and x_r - x_l == len(ys)
	if take == None:
		take = x_r - x_l
	assert 0 <= take <= x_r - x_l
	if len(ys) == 0 or take == 0:
		return R['X'](0)
	n, var, ys = len(ys), R['X'].gen(), list(map(R, ys))
	fact, invfact = [R(1)] * n, [R(1)] * n
	for i in range(1, n):
		fact[i] = fact[i - 1] * R(i)
	invfact[n - 1] = R(1) / fact[n - 1]
	for i in reversed(range(1, n - 1)):
		invfact[i] = invfact[i + 1] * R(i + 1)
	res, base = [R(0)] * take, R['X'](1)
	for i in map(R, range(x_l, x_r)):
		base *= var - i
		if base.degree() == take + 1:
			base -= base.coefficient(take + 1) * var**(take + 1)
		assert base.degree() <= take
	for i in range(x_l, x_r):
		coef = ys[i - x_l] * invfact[i - x_l] * invfact[x_r - 1 - i] * R(-1 if x_r - 1 - i & 1 else 1)
		cur = [R(0)] * take
		if i == 0:
			assert base.coefficient(0) == R(0)
			cur = base.coefficients(sparse = False)[1:]
			while len(cur) < take:
				cur += [R['X'](0)]
		else:
			cur[0] = base[0] / R(-i)
			for j in range(1, take):
				cur[j] = (base[j] - cur[j - 1]) / R(-i)
		for j in range(take):
			res[j] += cur[j] * coef
	poly = R['X'](0)
	for c in reversed(res):
		poly = poly * var + c
	return poly

if __name__ == "__main__":
	from sage.all import Zmod
	mod = 998244353 * 1000000007
	R = Zmod(mod)
	RX = R['X']
	def test_lagrange_interpolation():
		deg = 9
		f = RX.random_element(deg)
		xs = [-10, 1, 4, 6, 10, 100, 20, 18, 19, 44]
		assert f == lagrange_interpolation(R, [(x, f(x)) for x in xs])
	def test_lagrange_interpolation_on_interval():
		deg = 30
		f = RX.random_element(deg)
		x_l, x_r = -19, -19 + deg + 1
		assert f == lagrange_interpolation_on_interval(R, x_l, x_r, [f(x) for x in range(x_l, x_r)])
	test_lagrange_interpolation()
	test_lagrange_interpolation_on_interval()
