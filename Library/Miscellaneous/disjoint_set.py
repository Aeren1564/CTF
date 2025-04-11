class disjoint_set:
	def __init__(self, n):
		self.n = n
		self.p = [-1] * self.n
		self._group_count = n
	def root(self, u):
		if self.p[u] < 0:
			return u
		self.p[u] = self.root(self.p[u])
		return self.p[u]
	def share(self, u, v):
		return self.root(u) == self.root(v)
	def merge(self, u, v):
		u, v = self.root(u), self.root(v)
		if u == v:
			return False
		if self.p[u] > self.p[v]:
			u, v = v, u
		self.p[u] += self.p[v]
		self.p[v] = u
		self._group_count -= 1
		return True
	def clear(self):
		self.p = [-1] * self.n
		self._group_count = self.n
	def group_count(self):
		return self._group_count
	def group_up(self):
		group = [[] for _ in range(self.n)]
		for i in range(self.n):
			group[self.root(i)].append(i)
		return [g for g in group if len(g) > 0]
