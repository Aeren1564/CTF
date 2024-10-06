class matroid_intersection:
	def __init__(self, n):
		self.n = n
		self.pv = [-1] * self.n
		self.q = [0] * (n + 1)
	def forward_edge(self, u):
		res = []
		self.m1.clear()
		for v in range(self.n):
			if self.state[v] and u != v:
				self.m1.insert(v)
		for v in range(self.n):
			if not self.state[v] and self.pv[v] == -1 and self.m1.check(v):
				res.append(v)
				self.pv[v] = u
		return res
	def backward_edge(self, u):
		self.m2.clear()
		for it in range(2):
			for v in range(self.n):
				if (u == v or self.state[v]) and int(self.pv[v] == -1) == it:
					if not self.m2.check(v):
						if it:
							self.q[self.end], self.end, self.pv[v] = v, self.end + 1, u
							return v
						else:
							return -1
					self.m2.insert(v)
		return self.n
	def augment(self):
		self.pv = [-1] * self.n
		self.q[0] = self.n
		beg, self.end = 0, 1
		while beg < self.end:
			u, beg = self.q[beg], beg + 1
			for w in self.forward_edge(u):
				while (v := self.backward_edge(w)) >= 0:
					if v == self.n:
						while w != self.n:
							self.state[w], w = not self.state[w], self.pv[w]
						return True
		return False
	def maximum_common_independent_set(self, m1, m2):
		self.m1 = m1
		self.m2 = m2
		self.state = [False] * self.n
		self.m1.clear()
		self.m2.clear()
		for u in range(self.n):
			if self.m1.check(u) and self.m2.check(u):
				self.state[u] = True
				self.m1.insert(u)
				self.m2.insert(u)
		while self.augment():
			pass
		return [u for u in range(self.n) if self.state[u]]

class colorful_matroid:
	def __init__(self, color):
		self.flag = 0
		self.color = color
	def check(self, i):
		return self.flag >> self.color[i] & 1 == 0
	def insert(self, i):
		self.flag ^= 1 << self.color[i]
	def clear(self):
		self.flag = 0

class graphic_matroid:
	from disjoint_set import disjoint_set
	def __init__(self, V, edges):
		self.V = V
		self.edges = edges
		self.ds = disjoint_set(V)
	def check(self, i):
		return not self.ds.share(self.edges[i][0], self.edges[i][1])
	def insert(self, i):
		assert self.ds.merge(self.edges[i][0], self.edges[i][1])
	def clear(self):
		self.ds.clear()

class F2_linear_matroid:
	def __init__(self, elem):
		self.elem = elem
		self.basis = []
	def reduce(self, x):
		for b in self.basis:
			x = min(x, x ^ b)
		return x
	def check(self, i):
		return self.reduce(self.elem[i]) != 0
	def insert(self, i):
		x = self.reduce(self.elem[i])
		assert x > 0
		for i, b in enumerate(self.basis):
			if x > b:
				self.basis.insert(i, x)
				x = -1
				break
		if x != -1:
			self.basis.append(x)
	def clear(self):
		self.basis = []