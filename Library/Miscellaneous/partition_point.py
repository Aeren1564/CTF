# Assume its existence, find the integer ans with low <= ans <= high where
# 1. for all index i with low <= i < ans, pred(i) = True and
# 2. for all index i with ans <= i < high, pred(i) = False
# for some binary predicate pred: [low, high) -> bool
def partition_point(low: int, high: int, pred):
	assert low <= high
	low -= 1
	while high - low >= 2:
		mid = (low + high) // 2
		if pred(mid):
			low = mid
		else:
			high = mid
	return high
