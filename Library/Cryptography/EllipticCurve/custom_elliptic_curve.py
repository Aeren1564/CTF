class _custom_elliptic_curve_point:
	def __init__(self, p, params, x, y):
		self.p = int(p)
		self.params = list(map(int, params))
		self._x = int(x) % p if x != None else None
		self._y = int(y) % p if y != None else None
	def x(self):
		return self._x
	def y(self):
		return self._y
	def xy(self):
		return (self._x, self._y)
	def is_origin(self):
		return self._x == None
	def __eq__(self, other):
		assert isinstance(other, _custom_elliptic_curve_point)
		return self.p == other.p and self.params == other.params and self._x == other._x and self._y == other._y
	def __neg__(self):
		if self.is_origin():
			return self
		return _custom_elliptic_curve_point(self.p, self.params, self._x, (-self.params[0] * self._x - self.params[2] - self._y) % self.p)
	def _double(self):
		if self.is_origin():
			return self
		lam = (3 * self._x**2 + 2 * self.params[1] * self._x - self.params[0] * self._y + self.params[3]) * pow(2 * self._y + self.params[0] * self._x + self.params[2], -1, self.p) % self.p
		x3 = (lam**2 + self.params[0] * lam - self.params[1] - 2 * self._x) % self.p
		y3 = (-self.params[0] * x3 - self.params[2] - lam * x3 + lam * self._x - self._y) % self.p
		return _custom_elliptic_curve_point(self.p, self.params, x3, y3)
	def __add__(self, other):
		assert isinstance(other, _custom_elliptic_curve_point)
		if self.is_origin():
			return other
		if other.is_origin():
			return self
		if self == other:
			return self._double()
		if -self == other:
			return _custom_elliptic_curve_point(self.p, self.params, None, None)
		lam = (other._y - self._y) * pow(other._x - self._x, -1, self.p) % self.p
		x3 = (lam**2 + self.params[0] * lam - self.params[1] - self._x - other._x) % self.p
		y3 = (-self.params[0] * x3 - self.params[2] - lam * x3 + lam * self._x - self._y) % self.p
		return _custom_elliptic_curve_point(self.p, self.params, x3, y3)
	def __sub__(self, other):
		assert isinstance(other, _custom_elliptic_curve_point)
		return self + (-other)
	def __mul__(self, m: int):
		m = int(m)
		if m == 0:
			return _custom_elliptic_curve_point(self.p, self.params, None, None)
		if m < 0:
			return (-self).__mul__(-m)
		res = _custom_elliptic_curve_point(self.p, self.params, None, None)
		base = _custom_elliptic_curve_point(self.p, self.params, self._x, self._y)
		while m > 0:
			if m & 1:
				res += base
			base = base._double()
			m >>= 1
		return res
	def __rmul__(self, m):
		return self * m
	def __repr__(self):
		return f"ECPoint({self._x},{self._y})"
	def __iter__(self):
		for v in [self._x, self._y]:
			yield int(v)
# Allows singular curve
class custom_elliptic_curve:
	# if len(params) = 2, define the curve Y^2 = X^3 + params[0] * X + params[1]
	# if len(params) = 3, define the curve Y^2 = X^3 + params[0] * X**2 + params[1] * X + params[1]
	# if len(params) = 5, define the curve Y^2 + params[0] * X * Y + params[2] * Y = X**3 + params[1] * X**2 + params[3] * X + params[4]
	def __init__(self, p, params):
		params = list(map(int, params))
		if len(params) == 2: 
			params = [0, 0, 0, params[0], params[1]]
		if len(params) == 3:
			params = [0, params[0], 0, params[1], params[2]]
		assert len(params) == 5 # Y^2
		self.p = int(p)
		self.params = params
	def _on_curve(self, x, y):
		return (y**2 + self.params[0] * x * y + self.params[2] * y) % self.p == (x**3 + self.params[1] * x**2 + self.params[3] * x + self.params[4]) % self.p
	def discriminant(self):
		a1, a2, a3, a4, a6 = self.params
		b2 = (a1**2 + 4 * a2) % self.p
		b4 = (2 * a4 + a1 * a3) % self.p
		b6 = (a3**2 + 4 * a6) % self.p
		b8 = (a1**2 * a6 + 4 * a2 * a6 - a1 * a3 * a4 + a2 * a3**2 - a4**2) % self.p
		return (-b2**2 * b8 - 8 * b4**3 - 27 * b6**2 + 9 * b2 * b4 * b6) % self.p
	def __call__(self, x, y):
		if x != None:
			x = int(x)
		if y != None:
			y = int(y)
		if x == None or y == None:
			assert x == None and y == None
		else:
			assert self._on_curve(x, y);
		return _custom_elliptic_curve_point(self.p, self.params, x, y)
	def origin(self):
		return self.__call__(None, None)
	def __repr__(self):
		return f"EC mod {self.p} with param {self.params}"

if __name__ == "__main__":
	from sage.all import Integer, GF, EllipticCurve
	def check_eq(A, B):
		return int(A.x()) == int(B.x()) and int(A.y()) == int(B.y())
	p = 10**9 + 7
	F = GF(p)
	params5 = [123, 2323, 123432, 4323, 12313]
	for l in [2, 5]:
		params = params5[: l]
		EC = EllipticCurve(F, params)
		EC2 = custom_elliptic_curve(p, params)
		assert int(EC.discriminant()) == EC2.discriminant()
		P, Q = EC.lift_x(Integer(12334)), EC.lift_x(Integer(1921))
		P2, Q2 = EC2(P.x(), P.y()), EC2(Q.x(), Q.y())
		assert check_eq(P, P2) and check_eq(Q, Q2)
		R, R2 = P + (-Q), P2 + (-Q2)
		assert check_eq(R, R2)
		R, R2 = P + P, P2 + P2
		assert check_eq(R, R2)
		R, R2 = P * 90134, P2 * 90134
		assert check_eq(R, R2)
		R, R2 = 90134 * P, 90134 * P2
		assert check_eq(R, R2)

"""
Tested on
- IronCTF2024/crypto/Backdoor
"""