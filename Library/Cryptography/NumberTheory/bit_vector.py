class _bit_vector:
	def __init__(self, data: list, flip: list):
		self.n = len(data)
		assert len(flip) == self.n
		for x in data:
			assert 0 <= x
		for x in flip:
			assert 0 <= x <= 1
		self.data = data[:]
		self.flip = flip[:]
	def copy(self):
		return _bit_vector(self.data[:], self.flip[:])
	def __lshift__(self, x):
		assert isinstance(x, int)
		assert 0 <= x <= self.n
		if x == 0:
			return _bit_vector(self.data, self.flip)
		return _bit_vector([0] * x + self.data[:-x], [0] * x + self.flip[:-x])
	def rotl(self, x):
		assert isinstance(x, int)
		assert 0 <= x <= self.n
		if x == 0:
			return _bit_vector(self.data, self.flip)
		return _bit_vector(self.data[-x:] + self.data[:-x], self.flip[-x:] + self.flip[:-x])
	def __rshift__(self, x):
		assert isinstance(x, int)
		assert 0 <= x <= self.n
		if x == 0:
			return _bit_vector(self.data, self.flip)
		return _bit_vector(self.data[x:] + [0] * x, self.flip[x:] + [0] * x)
	def rotr(self, x):
		assert isinstance(x, int)
		assert 0 <= x <= self.n
		if x == 0:
			return _bit_vector(self.data, self.flip)
		return _bit_vector(self.data[x:] + self.data[:x], self.flip[x:] + self.flip[:x])
	# x is integer or _bit_vector
	def __xor__(self, x):
		assert isinstance(x, (int, _bit_vector))
		if isinstance(x, int):
			assert 0 <= x < 2**self.n
			flip = self.flip[:]
			for i in range(self.n):
				flip[i] ^= x >> i & 1
			return _bit_vector(self.data, flip)
		else:
			assert self.n == x.n
			return _bit_vector([self.data[i] ^ x.data[i] for i in range(self.n)], [self.flip[i] ^ x.flip[i] for i in range(self.n)])
	# x must be an integer
	def __and__(self, x):
		assert isinstance(x, int)
		assert 0 <= x < 2**self.n
		data = self.data[:]
		flip = self.flip[:]
		for i in range(self.n):
			if ~x >> i & 1:
				data[i], flip[i] = 0, 0
		return _bit_vector(data, flip)
	def __or__(self, x):
		assert isinstance(x, int)
		assert 0 <= x < 2**self.n
		data = self.data[:]
		flip = self.flip[:]
		for i in range(self.n):
			if x >> i & 1:
				data[i], flip[i] = 0, 1
		return _bit_vector(data, flip)
	def __invert__(self):
		return _bit_vector(self.data, [1 - self.flip[i] for i in range(self.n)])
	def __ilshift__(self, x):
		assert isinstance(other, int)
		assert 0 <= x <= n
		self = self << x
		return self
	def inplace_rotl(self, x):
		assert isinstance(other, int)
		assert 0 <= x <= n
		self = self.rotl(x)
		return self
	def __irshift__(self, x):
		assert isinstance(other, int)
		assert 0 <= x <= n
		self = self >> x
		return self
	def inplace_rotr(self, x):
		assert isinstance(other, int)
		assert 0 <= x <= n
		self = self.rotr(x)
		return self
	def __ixor__(self, other):
		assert isinstance(x, (int, _bit_vector))
		self = self ^ other
		return self
	def __iand__(self, other):
		assert isinstance(other, int)
		self = self & other
		return self
	def __ior__(self, other):
		assert isinstance(other, int)
		self = self | other
		return self
	def fold(self):
		folded_data, folded_flip = 0, 0
		for x in self.data:
			folded_data ^= x
		for x in self.flip:
			folded_flip ^= x
		return folded_data, folded_flip
	# Returns mat * self
	def linear_transform(self, mat):
		assert isinstance(mat, list)
		data, flip = [], []
		for x in mat:
			d, f = (self & x).fold()
			data.append(d), flip.append(f)
		return _bit_vector(data, flip)
	def concat(self, other):
		assert isinstance(other, _bit_vector)
		return _bit_vector(self.data + other.data, self.flip + other.flip)
	def __getitem__(self, i):
		if isinstance(i, int):
			assert 0 <= i < self.n
			return self.data[i], self.flip[i]
		else:
			return _bit_vector(self.data[i], self.flip[i])
	def __setitem__(self, i, v):
		assert isinstance(i, int)
		assert 0 <= i < self.n
		self.data[i], self.flip[i] = v

def make_bit_vectors(ns: list, starting_index: int = 0):
	assert isinstance(starting_index, int)
	assert 0 <= starting_index
	bvs = []
	offset = starting_index
	for n in ns:
		assert(0 <= n)
		bvs.append(_bit_vector([1 << i for i in range(offset, offset + n)], [0] * n))
		offset += n
	return bvs
