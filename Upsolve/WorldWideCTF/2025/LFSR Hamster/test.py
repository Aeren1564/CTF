################################################################

# cnt = [0] * 16
# for mask in range(1 << 14):
# 	x = 0
# 	for i in range(14):
# 		if mask >> i & 1:
# 			x += 1 if i < 12 else 2
# 	cnt[min(x, 15)] += 1
# p = 0
# for x in cnt:
# 	p += (x / 2**14)**5
# p = p + (1 - p) / 2
# print(f"{p = }")

###############################################################

# import os

# class LFSRHamster:
# 	def __init__(self, key):
# 		self.state = [int(eb) for b in key for eb in bin(b)[2:].zfill(8)]
# 		self.taps = [0, 1, 2, 7]
# 		self.filter = [85, 45, 76, 54, 45, 35, 39, 37, 117, 13, 112, 64, 75, 117, 21, 40]
# 		for _ in range(128):
# 			self.clock()

# 	def xorsum(self, l):
# 		s = 0
# 		for x in l:
# 			s ^= x
# 		return s

# 	def clock(self):
# 		x = [self.state[i] for i in self.filter]
# 		self.state = self.state[1:] + [self.xorsum(self.state[p] for p in self.taps)]
# 		return x[min(sum(x), len(x) - 1)]


# trial = 10**7

# ratio = [0, 0]
# for _ in range(1000):
# 	print(f"Test #{_}")
# 	lfsr = LFSRHamster(os.urandom(16))
# 	output = []
# 	for _ in range(trial):
# 		output.append(lfsr.clock())
# 	print(f"Sampling")
# 	cnt = [0, 0]
# 	for i in range(0, trial - 128):
# 		cnt[
# 			output[i] ^
# 			output[i + 1] ^
# 			output[i + 2] ^
# 			output[i + 7] ^
# 			output[i + 128]
# 		] += 1
# 	if cnt[0] > cnt[1]:
# 		print(f"Win {cnt = }, {cnt[0] / (cnt[0] + cnt[1])}")
# 		ratio[1] += 1
# 	else:
# 		print(f"Loss {cnt = }, {cnt[0] / (cnt[0] + cnt[1])}")
# 		ratio[0] += 1
# 	print(f"{ratio = }")
# 	print()

################################################################

# import random

# n = 2 * 10**7
# p = 0.5002062218503432

# history = [0, 0]
# while True:
# 	cnt = [0, 0]
# 	for _ in range(n):
# 		cnt[random.random() < p] += 1
# 	if cnt[0] < cnt[1]:
# 		history[1] += 1
# 		print(f"OK {cnt = }")
# 	else:
# 		history[0] += 1
# 		print(f":( {cnt = }")
# 	print(f"{history = }")
# 	print()

##################################################################

def success_probability(n, p):
	from math import erf, sqrt
	def phi(x):
		return (1 + erf(x / sqrt(2))) / 2
	return 1 - phi(-(p - 0.5) / sqrt(p * (1 - p)) * sqrt(n))

# n = 2 * 10**7
# p = 0.5002062218503432
n = 10**7
p = 0.5004

print(f"{success_probability(n, p) = }")