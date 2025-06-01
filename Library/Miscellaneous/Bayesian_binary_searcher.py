class Bayesian_binary_searcher:
	# Assume its existence, the goal is to find the integer ans with low <= ans <= high where
	# 1. for all index i with low <= ans < p, pred(i) = True and
	# 2. for all index i with p <= ans < high, pred(i) = False
	# for some binary predicate pred: [low, high) -> bool
	def __init__(self, low, high, eps = 1e-9):
		assert isinstance(low, int) and isinstance(high, int) and low <= high
		self.low = low
		self.high = high
		self.PMF = [(low, high + 1, 1.0 / (high - low + 1))]
		self.eps = eps
	def _renormalize(self):
		tot = sum((r - l) * p for l, r, p in self.PMF)
		self.PMF = [(l, r, p / tot) for l, r, p in self.PMF]
	# Returns the smallest x where sum(PMF[low, x)) >= 1/2
	def half_index(self):
		s = 0.0
		for l, r, density in self.PMF:
			s_cur = (r - l) * density
			if s + s_cur >= 0.5:
				return int(l + (0.5 - s) / s_cur * (r - l))
			s += s_cur
		assert False
	# The caller can observe an event E associated with x
	# prob is either a pair (pL, pR) or a triple (pL, pM, pR)
	# If it is a pair,
	# - pL is the probability of E occuring if ans = i for any i < x
	# - pR is the probability of E occuring if ans = i for any i >= x
	#	If it is a triple,
	# - pL is the probability of E occuring if ans = i for any i < x
	# - pM is the probability of E occuring if ans = x
	# - pR is the probability of E occuring if ans = i for any i > x
	# Update self.PMF according to E
	# Recommended to use x = self.half_index()
	# See https://en.wikipedia.org/wiki/Bayesian_inference#Formal_explanation
	def update(self, x, prob):
		assert self.low <= x <= self.high
		assert len(prob) in [2, 3]
		assert abs(1 - sum(prob)) <= self.eps
		assert 0 <= min(prob)
		prob = list(map(float, prob))
		PMF_next = []
		update_with = []
		if len(prob) == 2:
			update_with = [(l, r, p) for l, r, p in [(self.low, x, prob[0]), (x, self.high, prob[1])] if l < r and p > 0]
		else:
			update_with = [(l, r, p) for l, r, p in [(self.low, x, prob[0]), (x, x + 1, prob[1]), (x + 1, self.high, prob[2])] if l < r and p > 0]
		for l, r, p in self.PMF:
			for ul, ur, up in update_with:
				cl, cr, cp = max(l, ul), min(r, ur), p * up
				if cl < cr and cp > 0:
					PMF_next.append((cl, cr, cp))
		self.PMF = PMF_next
		self._renormalize()
	# Returns the smallest index with the maximum probability of being the ans
	def guess_ans(self):
		ans = None
		opt = -1
		for l, r, p in self.PMF:
			if opt < p:
				ans = l
				opt = p
		return ans

"""
Tested on
- D3CTF 2025 d3guess
"""