# Assume its existence and find the index p with low <= p <= high where
# 1. for all index i with low <= i < p, pred(i) = True and
# 2. for all index i with p <= i < high, pred(i) = False
def partition_point(low: int, high: int, pred):
	assert low < high
	while high - low >= 2:
		mid = (low + high) // 2
		if pred(mid):
			low = mid
		else:
			high = mid
	return high