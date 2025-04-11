"""
Let E be an elliptic curve, possibly singular, over a ring R given by the Weierstrass equation
 Y^2 + coef[0] * XY + coef[2] * Y = X^3 + coef[1] * X^2 + coef[3] * X + coef[4]
where 2 and 3 has multiplicative inverse
"""
class EC_coordinate_normalizer:
	def __init__(self, R, init_coef):
		from copy import copy
		assert len(init_coef) == 5
		self.R = copy(R)
		self.init_coef = list(map(R, init_coef))
		self.coef = list(map(R, init_coef))
		self.coef = [
			(self.coef[1] + self.coef[0]**2 / self.R(4)) / self.R(3),
			self.coef[3] + self.coef[0] * self.coef[2] / self.R(2),
			self.coef[4] + self.coef[2]**2 / self.R(4)
		]
		self.coef = [
			self.coef[1] - self.R(3) * self.coef[0]**2,
			self.R(2) * self.coef[0]**3 - self.coef[0] * self.coef[1] + self.coef[2]
		]
	# returns (a, b) where Y^2 = X^3 + a*X + b is the equivalent elliptic curve
	def get_coef(self):
		return self.coef[:]
	# get the corresponding point on Y^2 = X^3 + a*X + b
	def map(self, x, y):
		x, y = self.R(x), self.R(y)
		assert y**2 + self.init_coef[0] * x * y + self.init_coef[2] * y == x**3 + self.init_coef[1] * x**2 + self.init_coef[3] * x + self.init_coef[4], f"[ERROR]<EC_coordinate_normalizer> the point is not on the curve"
		y += (self.init_coef[0] * x + self.init_coef[2]) / self.R(2)
		x += (self.init_coef[1] + self.init_coef[0]**2 / self.R(4)) / self.R(3)
		assert y**2 == x**3 + self.coef[0] * x + self.coef[1], f"[ERROR]<EC_coordinate_normalizer> there's something wrong with the implementation"
		return x, y
